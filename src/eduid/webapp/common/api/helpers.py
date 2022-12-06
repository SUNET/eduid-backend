# -*- coding: utf-8 -*-
import warnings
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type, TypeVar, Union, cast, overload

from flask import current_app, render_template, request

from eduid.common.config.base import EduIDBaseAppConfig, EduidEnvironment, MagicCookieMixin, MailConfigMixin
from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.exceptions import NoNavetData
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, DeregistrationInformation, FullPostalAddress
from eduid.userdb import NinIdentity
from eduid.userdb.element import ElementKey
from eduid.userdb.identity import IdentityType
from eduid.userdb.logs.element import (
    NinProofingLogElement,
    TForeignIdProofingLogElementSubclass,
    TNinProofingLogElementSubclass,
)
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.proofing.state import NinProofingState, OidcProofingState
from eduid.userdb.user import TUserSubclass, User
from eduid.userdb.userdb import UserDB
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.utils import get_from_current_app
from eduid.common.rpc.am_relay import AmRelay
from eduid.userdb.logs import ProofingLog
from eduid.common.rpc.mail_relay import MailRelay
from eduid.webapp.email.settings.common import EmailConfig
from eduid.common.rpc.msg_relay import MsgRelay

__author__ = "lundberg"


def set_user_names_from_official_address(
    user: TUserSubclass, proofing_log_entry: TNinProofingLogElementSubclass
) -> TUserSubclass:
    """
    :param user: Proofing app private userdb user
    :param proofing_log_entry: Proofing log entry element

    :returns: User object
    """
    user.given_name = proofing_log_entry.user_postal_address.name.given_name
    user.surname = proofing_log_entry.user_postal_address.name.surname
    if user.given_name is None or user.surname is None:
        # please mypy
        raise RuntimeError("No given name or surname found in proofing log user postal address")
    given_name_marking = proofing_log_entry.user_postal_address.name.given_name_marking
    user.display_name = f"{user.given_name} {user.surname}"
    if given_name_marking:
        _name_index = (int(given_name_marking) // 10) - 1  # ex. "20" -> 1 (second GivenName is real given name)
        try:
            _given_name = user.given_name.split()[_name_index]
            user.display_name = f"{_given_name} {user.surname}"
        except IndexError:
            # At least occasionally, we've seen GivenName 'Jan-Erik Martin' with GivenNameMarking 30
            pass
    current_app.logger.info("User names set from official address")
    current_app.logger.debug(
        f"{proofing_log_entry.user_postal_address.name} resulted in given_name: {user.given_name}, "
        f"surname: {user.surname} and display_name: {user.display_name}"
    )
    return user


def set_user_names_from_foreign_id(
    user: TUserSubclass, proofing_log_entry: TForeignIdProofingLogElementSubclass, display_name: Optional[str] = None
) -> TUserSubclass:
    """
    :param user: Proofing app private userdb user
    :param proofing_log_entry: Proofing log entry element
    :param display_name: If any other display name than given name + surname should be used

    :returns: User object
    """
    user.given_name = proofing_log_entry.given_name
    user.surname = proofing_log_entry.surname
    user.display_name = f"{user.given_name} {user.surname}"
    if display_name is not None:
        user.display_name = display_name
    return user


def number_match_proofing(user: User, proofing_state: OidcProofingState, number: str) -> bool:
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param number: National identity number

    :return: True|False
    """
    if proofing_state.nin.number == number:
        return True
    current_app.logger.error(f"Self asserted NIN does not match for user {user}")
    current_app.logger.debug(f"Self asserted NIN: {proofing_state.nin.number}. NIN from vetting provider {number}")
    return False


def add_nin_to_user(user: User, proofing_state: NinProofingState) -> None:
    am_relay = get_from_current_app("am_relay", AmRelay)
    private_userdb = cast(UserDB[User], get_from_current_app("private_userdb", UserDB))
    # Add nin to user if not already there
    if not user.identities.nin:
        current_app.logger.info(f"Adding NIN for user {user}")
        current_app.logger.debug(f"Self asserted NIN: {proofing_state.nin.number}")
        nin_identity = NinIdentity(
            created_by=proofing_state.nin.created_by,
            created_ts=proofing_state.nin.created_ts,
            is_verified=False,  # always add a nin identity as unverified
            number=proofing_state.nin.number,
        )
        user.identities.add(nin_identity)
        user.modified_ts = utc_now()
        # Save user to private db
        private_userdb.save(user, check_sync=False)
        # Ask am to sync user to central db
        current_app.logger.info(f"Request sync for user {user}")
        result = am_relay.request_user_sync(user)
        current_app.logger.info(f"Sync result for user {user}: {result}")
    return None


def verify_nin_for_user(
    user: User, proofing_state: NinProofingState, proofing_log_entry: NinProofingLogElement
) -> bool:
    """
    Mark a nin on a user as verified, after logging data about the proofing to the proofing log.

    If this function is given a ProofingUser instance, the instance will be updated accordingly and
    the calling function won't need to reload the user from the central database to access the updated
    NIN element.

    :param user: Any kind of User
    :param proofing_state: Proofing state for user
    :param proofing_log_entry: Proofing log entry element

    :return: Success or not
    """
    am_relay = get_from_current_app("am_relay", AmRelay)
    private_userdb = cast(UserDB[User], get_from_current_app("private_userdb", UserDB))
    proofing_log = get_from_current_app("am_relay", ProofingLog)

    # add an unverified nin identity to the user if it does not exist yet
    if user.identities.nin is None:
        add_nin_to_user(user=user, proofing_state=proofing_state)

    # please mypy
    assert user.identities.nin is not None

    # Check if the NIN is already verified
    if user.identities.nin.is_verified:
        current_app.logger.info("User already has a verified NIN")
        current_app.logger.debug(f"NIN: {user.identities.nin.number}")
        return True

    # check if the users current nin is the same as the one just verified
    # if there is no locked nin identity or the locked nin identity matches we can replace the current nin identity
    # with the one just verified
    if user.identities.nin.number != proofing_state.nin.number:
        current_app.logger.info("users current nin does not match the nin just verified")
        current_app.logger.debug(f"{user.identities.nin.number} != {proofing_state.nin.number}")
        if user.locked_identity.nin is not None and user.locked_identity.nin.number != proofing_state.nin.number:
            raise ValueError("users locked nin does not match verified nin")

        # user has no locked nin identity or the user has previously verified the nin
        # replace the never verified nin with the one just verified
        user.identities.remove(ElementKey(IdentityType.NIN.value))
        nin_identity = NinIdentity(
            number=proofing_state.nin.number,
            created_ts=proofing_state.nin.created_ts,
            created_by=proofing_state.nin.created_by,
        )
        user.identities.add(nin_identity)
        current_app.logger.info("replaced users current nin with the one just verified")

    # Update users nin identity
    user.identities.nin.is_verified = True
    # Ensure matching timestamp in verification log entry, and NIN element on user
    user.identities.nin.verified_ts = proofing_log_entry.created_ts
    user.identities.nin.verified_by = proofing_state.nin.created_by

    # Update users name
    user = set_user_names_from_official_address(user, proofing_log_entry)

    # If user was updated successfully continue with logging the proof and saving the user to central db
    # Send proofing data to the proofing log
    if not proofing_log.save(proofing_log_entry):
        return False
    current_app.logger.info(f"Recorded nin identity verification in the proofing log")

    # Save user to private db
    private_userdb.save(user)

    # Ask am to sync user to central db
    current_app.logger.info(f"Request sync for user {user}")
    result = am_relay.request_user_sync(user)
    current_app.logger.info(f"Sync result for user {user}: {result}")

    return True


def send_mail(
    subject: str,
    to_addresses: List[str],
    text_template: str,
    html_template: str,
    app: EduIDBaseApp,
    context: Optional[dict[str, Any]] = None,
    reference: Optional[str] = None,
):
    """
    :param subject: subject text
    :param to_addresses: email addresses for the to field
    :param text_template: text message as a jinja template
    :param html_template: html message as a jinja template
    :param app: Flask current app
    :param context: template context
    :param reference: Audit reference to help cross-reference audit log and events
    """
    mail_relay = get_from_current_app("mail_relay", MailRelay)
    conf = get_from_current_app("conf", EmailConfig)

    site_name = conf.eduid_site_name
    site_url = conf.eduid_site_url

    default_context: Dict[str, str] = {
        "site_url": site_url,
        "site_name": site_name,
    }
    if not context:
        context = {}
    context.update(default_context)

    app.logger.debug(f"subject: {subject}")
    app.logger.debug(f"to addresses: {to_addresses}")
    text = render_template(text_template, **context)
    app.logger.debug(f"rendered text: {text}")
    html = render_template(html_template, **context)
    app.logger.debug(f"rendered html: {html}")
    mail_relay.sendmail(subject, to_addresses, text, html, reference)


def check_magic_cookie(config: MagicCookieMixin) -> bool:
    """
    This is for use in backdoor views, to check whether the backdoor is open.

    This checks that the environment allows the use of magic_cookies, that there is a magic cookie,
    and that the content of the magic cookie coincides with the configured magic cookie.

    :param config: A configuration object
    """
    if config.environment not in [EduidEnvironment.dev, EduidEnvironment.staging]:
        return False

    if not config.magic_cookie or not config.magic_cookie_name:
        current_app.logger.error(f"Magic cookie parameters not present in configuration for {config.environment}")
        return False

    cookie = request.cookies.get(config.magic_cookie_name)
    if cookie is None:
        current_app.logger.info(f"Got no magic cookie (named {config.magic_cookie_name})")
        return False

    if cookie == config.magic_cookie:
        current_app.logger.info("check_magic_cookie check success")
        return True

    current_app.logger.info("check_magic_cookie check fail")
    return False


@dataclass
class ProofingNavetData:
    user_postal_address: Optional[FullPostalAddress] = None
    deregistration_information: Optional[DeregistrationInformation] = None


def get_proofing_log_navet_data(nin: str) -> ProofingNavetData:
    msg_relay = get_from_current_app("msgl_relay", MsgRelay)

    navet_data = msg_relay.get_all_navet_data(nin=nin, allow_deregistered=True)
    # the only cause for deregistration we allow is emigration
    if (
        navet_data.person.is_deregistered()
        and navet_data.person.deregistration_information.cause_code is not DeregisteredCauseCode.EMIGRATED
    ):
        # please type checking
        assert navet_data.person.deregistration_information.cause_code is not None
        raise NoNavetData(
            f"Person deregistered with code {navet_data.person.deregistration_information.cause_code.value}"
        )

    user_postal_address = FullPostalAddress(
        name=navet_data.person.name, official_address=navet_data.person.postal_addresses.official_address
    )
    return ProofingNavetData(
        user_postal_address=user_postal_address,
        deregistration_information=navet_data.person.deregistration_information,
    )
