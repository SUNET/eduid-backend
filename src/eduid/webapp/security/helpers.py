from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import unique
from typing import Optional

from flask_babel import gettext as _

from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.msg_relay import FullPostalAddress, NavetData
from eduid.userdb import NinIdentity
from eduid.userdb.logs.element import NameUpdateProofing
from eduid.userdb.security import SecurityUser
from eduid.userdb.user import User
from eduid.webapp.common.api.helpers import send_mail, set_user_names_from_official_address
from eduid.webapp.common.api.messages import FluxData, TranslatableMsg, error_response
from eduid.webapp.common.authn.utils import generate_password
from eduid.webapp.common.session.namespaces import SP_AuthnRequest
from eduid.webapp.security.app import current_security_app as current_app

__author__ = "lundberg"


@unique
class SecurityMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # Too much time passed since re-authn for account termination
    stale_reauthn = "security.stale_authn_info"
    # No reauthn
    no_reauthn = "security.no_reauthn"
    # removing a verified NIN is not allowed
    rm_verified = "nins.verified_no_rm"
    # success removing nin
    rm_success = "nins.success_removal"
    # the user already has the nin
    already_exists = "nins.already_exists"
    # success adding a new nin
    add_success = "nins.successfully_added"
    # The user tried to register more than the allowed number of tokens
    max_webauthn = "security.webauthn.max_allowed_tokens"
    # the account has to have personal data to be able to register webauthn data
    no_pdata = "security.webauthn-missing-pdata"
    # success registering webauthn token
    webauthn_success = "security.webauthn_register_success"
    # It is not allowed to remove the last webauthn credential left
    no_last = "security.webauthn-noremove-last"
    # Success removing webauthn token
    rm_webauthn = "security.webauthn-token-removed"
    # old_password or new_password missing
    chpass_no_data = "security.change_password_no_data"
    # weak password
    chpass_weak = "security.change_password_weak"
    # wrong old password
    unrecognized_pw = "security.change_password_wrong_old_password"
    # new change password
    change_password_success = "security.change-password-success"
    # old change password
    chpass_password_changed2 = "chpass.password-changed"
    # throttled user update
    user_update_throttled = "security.user-update-throttled"
    user_not_verified = "security.user-not-verified"
    navet_data_incomplete = "security.navet-data-incomplete"
    user_updated = "security.user-updated"
    no_webauthn = "security.webauthn-token-notfound"
    invalid_authenticator = "security.webauthn-invalid-authenticator"
    missing_registration_state = "security.webauthn-missing-registration-state"
    webauthn_attestation_fail = "security.webauthn-attestation-fail"
    webauthn_metadata_fail = "security.webauthn-metadata-fail"


@dataclass
class CredentialInfo:
    key: str
    credential_type: str
    created_ts: datetime
    success_ts: Optional[datetime]
    verified: bool = False
    description: Optional[str] = None


def compile_credential_list(user: User) -> list[CredentialInfo]:
    """
    Make a list of a users credentials, with extra information, for returning in API responses.
    """
    credentials: list[CredentialInfo] = []
    authn_info = current_app.authninfo_db.get_authn_info(user)
    for cred_key, authn in authn_info.items():
        cred = user.credentials.find(cred_key)
        # pick up attributes not present on all types of credentials
        _description: Optional[str] = None
        _is_verified = False
        _d = getattr(cred, "description", None)
        if isinstance(_d, str):
            _description = _d
        _is_v = getattr(cred, "is_verified", None)
        if isinstance(_is_v, bool):
            _is_verified = _is_v
        info = CredentialInfo(
            key=cred_key,
            credential_type=authn.credential_type.value,
            created_ts=authn.created_ts,
            description=_description,
            success_ts=authn.success_ts,
            verified=_is_verified,
        )
        credentials.append(info)
    return credentials


def remove_nin_from_user(security_user: SecurityUser, nin: NinIdentity) -> None:
    """
    :param security_user: Private userdb user
    :param nin: NIN to remove
    """
    security_user.identities.remove(nin.key)
    # Save user to private db
    current_app.private_userdb.save(security_user)
    # Ask am to sync user to central db
    current_app.logger.debug(f"Request sync for user {security_user}")
    result = current_app.am_relay.request_user_sync(security_user)
    current_app.logger.info(f"Sync result for user {security_user}: {result}")


def generate_suggested_password() -> str:
    """
    The suggested password is saved in session to avoid form hijacking
    """
    password_length = current_app.conf.password_length

    password = generate_password(length=password_length)
    password = " ".join([password[i * 4 : i * 4 + 4] for i in range(0, int(len(password) / 4))])

    return password


def send_termination_mail(user):
    """
    :param user: User object
    :type user: User

    Sends a termination mail to all verified mail addresses for the user.
    """
    subject = _("Terminate account")
    text_template = "termination_email.txt.jinja2"
    html_template = "termination_email.html.jinja2"
    to_addresses = [address.email for address in user.mail_addresses.verified]
    send_mail(subject, to_addresses, text_template, html_template, current_app)
    current_app.logger.info("Sent termination email to user.")


def check_reauthn(authn: Optional[SP_AuthnRequest], max_age: timedelta) -> Optional[FluxData]:
    """Check if a re-authentication has been performed recently enough for this action"""
    if not authn or not authn.authn_instant:
        current_app.logger.info(f"Action requires re-authentication")
        return error_response(message=SecurityMsg.no_reauthn)

    if authn.consumed:
        current_app.logger.info(f"The authentication presented has already been consumed")
        return error_response(message=SecurityMsg.no_reauthn)

    delta = utc_now() - authn.authn_instant

    if delta > max_age:
        current_app.logger.info(f"Re-authentication age {delta} too old")
        return error_response(message=SecurityMsg.stale_reauthn)

    return None


def update_user_official_name(security_user: SecurityUser, navet_data: NavetData) -> bool:
    # please mypy
    if security_user.identities.nin is None:
        return False

    # Compare current names with what we got from Navet
    if (
        security_user.given_name != navet_data.person.name.given_name
        or security_user.surname != navet_data.person.name.surname
    ):
        user_postal_address = FullPostalAddress(
            name=navet_data.person.name,
            official_address=navet_data.person.postal_addresses.official_address,
        )
        proofing_log_entry = NameUpdateProofing(
            created_by="security",
            eppn=security_user.eppn,
            proofing_version="2021v1",
            nin=security_user.identities.nin.number,
            previous_given_name=security_user.given_name or None,  # default to None for empty string
            previous_surname=security_user.surname or None,  # default to None for empty string
            user_postal_address=user_postal_address,
        )
        # Update user names
        security_user = set_user_names_from_official_address(security_user, proofing_log_entry)

        # Do not save the user if proofing log write fails
        if not current_app.proofing_log.save(proofing_log_entry):
            current_app.logger.error("Proofing log write failed")
            current_app.logger.debug(f"proofing_log_entry: {proofing_log_entry}")
            return False

        current_app.logger.info(f"Recorded verification in the proofing log")
        # Save user to private db
        current_app.private_userdb.save(security_user)
        # Ask am to sync user to central db
        current_app.logger.info("Request sync for user")
        result = current_app.am_relay.request_user_sync(security_user)
        current_app.logger.info(f"Sync result for user {security_user}: {result}")
        current_app.stats.count(name="refresh_user_data_name_updated")

    return True
