import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from enum import unique
from http import HTTPStatus
from typing import Any

import requests
from flask import render_template
from flask_babel import gettext as _
from oic.oic.message import ClaimsRequest

from eduid.userdb import User
from eduid.userdb.logs import SeLegProofing, SeLegProofingFrejaEid
from eduid.userdb.proofing import OidcProofingState
from eduid.userdb.proofing.element import NinProofingElement
from eduid.userdb.proofing.user import ProofingUser
from eduid.webapp.common.api.helpers import number_match_proofing, verify_nin_for_user
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.api.utils import get_unique_hash
from eduid.webapp.oidc_proofing.app import current_oidcp_app as current_app

__author__ = "lundberg"


@unique
class OIDCMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # Connection error sending a request to the authz endpoint
    no_conn = "No connection to authorization endpoint"


def create_proofing_state(user: User, nin: str) -> OidcProofingState:
    """
    :param user: Proofing user
    :param nin: National Identity Number

    :return: OidcProofingState
    """
    state = get_unique_hash()
    nonce = get_unique_hash()
    token = get_unique_hash()
    nin_element = NinProofingElement(number=nin, created_by="oidc_proofing", is_verified=False)
    proofing_state = OidcProofingState(
        id=None, modified_ts=None, eppn=user.eppn, nin=nin_element, state=state, nonce=nonce, token=token
    )
    return proofing_state


def create_opaque_data(nonce: str, token: str) -> str:
    """
    :param nonce: Nonce
    :param token: Token

    :return: Opaque data for the user
    """
    # The "1" below denotes the version of the data exchanged, right now only version 1 is supported.
    return "1" + json.dumps({"nonce": nonce, "token": token})


def get_proofing_state_valid_until(proofing_state: OidcProofingState, expire_time_hours: int) -> datetime:
    """
    :param proofing_state: Proofing state for user
    :param expire_time_hours: Expire time in hours

    :return: Proofing state valid until
    """
    assert proofing_state.modified_ts is not None  # please mypy
    grace_hours = 24 - proofing_state.modified_ts.hour  # Give the user the full day to complete
    return proofing_state.modified_ts + timedelta(hours=expire_time_hours + grace_hours)


def is_proofing_state_expired(proofing_state: OidcProofingState, expire_time_hours: int) -> bool:
    """
    :param proofing_state: Proofing state for user
    :param expire_time_hours: Expire time in hours

    :return: True/False
    """
    valid_until = get_proofing_state_valid_until(proofing_state, expire_time_hours)
    # Use tzinfo from timezone aware mongodb datetime
    if datetime.now(valid_until.tzinfo) > valid_until:
        return True
    return False


def do_authn_request(proofing_state: OidcProofingState, claims_request: ClaimsRequest, redirect_url: str) -> bool:
    """
    :param proofing_state: Proofing state for user
    :param claims_request: Requested claims
    :param redirect_url: authn response url

    :return: success
    """
    oidc_args = {
        "client_id": current_app.oidc_client.client_id,
        "response_type": "code",
        "scope": ["openid"],
        "redirect_uri": redirect_url,
        "state": proofing_state.state,
        "nonce": proofing_state.nonce,
        "claims": claims_request.to_json(),
    }
    current_app.logger.debug("AuthenticationRequest args:")
    current_app.logger.debug(oidc_args)

    if not current_app.oidc_client.authorization_endpoint:
        raise RuntimeError("No OIDC client authorization endpoint")

    response = requests.post(current_app.oidc_client.authorization_endpoint, data=oidc_args)
    if response.status_code == HTTPStatus.OK:
        current_app.logger.debug(
            "Authentication request delivered to provider {!s}".format(
                current_app.conf.provider_configuration_info["issuer"]
            )
        )
        return True
    current_app.logger.error(f"Bad response from OP: {response.status_code!s} {response.reason!s} {response.content!s}")
    return False


def send_new_verification_method_mail(user: User) -> None:
    site_name = current_app.conf.eduid_site_name
    site_url = current_app.conf.eduid_site_url
    subject = _("%(site_name)s account verification", site_name=site_name)

    if not user.mail_addresses.primary:
        current_app.logger.info("User has no primary e-mail address, can't send email requesting other vetting method")
        return None

    email_address = user.mail_addresses.primary.email

    context = {
        "site_url": site_url,
        "site_name": site_name,
    }

    text = render_template("redo_verification.txt.jinja2", **context)
    html = render_template("redo_verification.html.jinja2", **context)

    current_app.mail_relay.sendmail(subject, [email_address], text, html)
    current_app.logger.info(f"Sent email to user {user} requesting another vetting method")


def handle_seleg_userinfo(user: ProofingUser, proofing_state: OidcProofingState, userinfo: Mapping[str, Any]) -> None:
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param userinfo: userinfo from OP

    :return: None
    """
    current_app.logger.info(f"Verifying NIN from seleg for user {user}")
    number = userinfo["identity"]
    metadata = userinfo.get("metadata", {})
    if metadata.get("score", 0) == 100:
        if not number_match_proofing(user, proofing_state, number):
            current_app.logger.warning(
                "Proofing state number did not match number in userinfo. Using number from userinfo."
            )
            proofing_state.nin.number = number
        current_app.logger.info(f"Getting address for user {user}")
        # Lookup official address via Navet
        address = current_app.msg_relay.get_postal_address(proofing_state.nin.number, timeout=15)
        # Transaction id is the same data as used for the QR code
        transaction_id = metadata["opaque"]

        created_by = proofing_state.nin.created_by
        if created_by is None:
            created_by = "se-leg"

        proofing_log_entry = SeLegProofing(
            eppn=user.eppn,
            created_by=created_by,
            nin=proofing_state.nin.number,
            vetting_by="se-leg",
            transaction_id=transaction_id,
            user_postal_address=address,
            proofing_version="2017v1",
        )
        if not verify_nin_for_user(user, proofing_state, proofing_log_entry):
            current_app.logger.error(f"Verifying NIN for user {user} failed")
            # TODO: propagate error to caller
            return None
        current_app.stats.count(name="seleg.nin_verified")
    else:
        current_app.logger.info("se-leg proofing did not result in a verified account due to low score")
        current_app.stats.count(name="seleg.authn_response_with_low_score")
        send_new_verification_method_mail(user)


def handle_freja_eid_userinfo(user: User, proofing_state: OidcProofingState, userinfo: Mapping[str, Any]) -> None:
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param userinfo: userinfo from OP
    """
    current_app.logger.info(f"Verifying NIN from Freja eID for user {user}")
    number = userinfo["results"]["freja_eid"]["ssn"]
    opaque = userinfo["results"]["freja_eid"]["opaque"]
    transaction_id = userinfo["results"]["freja_eid"]["ref"]
    if not number_match_proofing(user, proofing_state, number):
        current_app.logger.warning("Proofing state number did not match number in userinfo.Using number from userinfo.")
        proofing_state.nin.number = number

    current_app.logger.info(f"Getting address for user {user}")
    # Lookup official address via Navet
    address = current_app.msg_relay.get_postal_address(proofing_state.nin.number, timeout=15)
    _created_by = proofing_state.nin.created_by
    assert _created_by is not None  # please mypy
    proofing_log_entry = SeLegProofingFrejaEid(
        eppn=user.eppn,
        created_by=_created_by,
        nin=proofing_state.nin.number,
        transaction_id=transaction_id,
        opaque_data=opaque,
        user_postal_address=address,
        proofing_version="2017v1",
        deregistration_information=None,
    )
    if not verify_nin_for_user(user, proofing_state, proofing_log_entry):
        current_app.logger.error(f"Verifying NIN for user {user} failed")
        # TODO: Propagate error to caller
        return None
    current_app.stats.count(name="freja.nin_verified")
