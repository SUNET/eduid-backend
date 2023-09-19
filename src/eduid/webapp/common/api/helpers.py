import warnings
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, TypeVar, Union, cast, overload

from flask import current_app, render_template, request

from eduid.common.config.base import EduidEnvironment, MagicCookieMixin, MailConfigMixin
from eduid.common.rpc.exceptions import NoNavetData
from eduid.common.rpc.mail_relay import MailRelay
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, DeregistrationInformation, FullPostalAddress, MsgRelay
from eduid.userdb import NinIdentity
from eduid.userdb.element import ElementKey
from eduid.userdb.exceptions import LockedIdentityViolation
from eduid.userdb.identity import IdentityProofingMethod, IdentityType
from eduid.userdb.logs import ProofingLog
from eduid.userdb.logs.element import (
    NinEIDProofingLogElement,
    NinNavetProofingLogElement,
    NinProofingLogElement,
    TForeignIdProofingLogElementSubclass,
    TNinEIDProofingLogElementSubclass,
    TNinNavetProofingLogElementSubclass,
    TNinProofingLogElementSubclass,
)
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.proofing.state import NinProofingState, OidcProofingState
from eduid.userdb.user import TUserSubclass, User
from eduid.userdb.userdb import UserDB
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.utils import get_from_current_app, save_and_sync_user

__author__ = "lundberg"


def get_marked_given_name(given_name: str, given_name_marking: Optional[str]) -> str:
    """
    Given name marking denotes up to two given names, and is used to determine
    which of the given names are to be primarily used in addressing a person.
    For this purpose, the given_name_marking is two numbers:
        indexing starting at 1
        the second can be 0 for only one mark
        hyphenated names are counted separately (i.e. Jan-Erik are two separate names)
            assuming they are always marked together as per example in documentation

    current version of documentation:
    https://www.skatteverket.se/download/18.2cf1b5cd163796a5c8bf20e/1530691773712/AllmanBeskrivning.pdf

    :param given_name: Given name
    :param given_name_marking: Given name marking

    :return: Marked given name (Tilltalsnamn)
    """
    if not given_name_marking or "00" == given_name_marking:
        return given_name

    # cheating with indexing
    _given_names: List[Optional[str]] = [None]
    for name in given_name.split():
        _given_names.append(name)
        if "-" in name:
            # hyphenated names are counted separately
            _given_names.append(None)
    _optional_marked_names: List[Optional[str]] = []
    for i in given_name_marking:
        _optional_marked_names.append(_given_names[int(i)])
    # remove None values
    # i.e. 0 index and hyphenated names second part placeholder
    _marked_names: List[str] = [name for name in _optional_marked_names if name is not None]
    return " ".join(list(_marked_names))


def set_user_names_from_nin_proofing(
    user: TUserSubclass,
    proofing_log_entry: TNinProofingLogElementSubclass,
) -> TUserSubclass:
    if isinstance(proofing_log_entry, NinNavetProofingLogElement):
        user = set_user_names_from_official_address(user, proofing_log_entry)
    elif isinstance(proofing_log_entry, NinEIDProofingLogElement):
        user = set_user_names_from_nin_eid_proofing(user, proofing_log_entry)
    else:
        raise RuntimeError("No given name, surname or user postal address found in proofing log entry")
    return user


def set_user_names_from_official_address(
    user: TUserSubclass, proofing_log_entry: TNinNavetProofingLogElementSubclass
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
        _given_name = get_marked_given_name(user.given_name, given_name_marking)
        user.display_name = f"{_given_name} {user.surname}"
    current_app.logger.info("User names set from official address")
    current_app.logger.debug(
        f"{proofing_log_entry.user_postal_address.name} resulted in given_name: {user.given_name}, "
        f"surname: {user.surname} and display_name: {user.display_name}"
    )
    return user


def set_user_names_from_nin_eid_proofing(
    user: TUserSubclass, proofing_log_entry: TNinEIDProofingLogElementSubclass
) -> TUserSubclass:
    user.given_name = proofing_log_entry.given_name
    user.surname = proofing_log_entry.surname
    user.display_name = f"{user.given_name} {user.surname}"
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


# Explain to mypy that if you call add_nin_to_user without a user_type, the return type will be ProofingUser
# but if you call it with a user_type the return type will be that type
TProofingUser = TypeVar("TProofingUser", bound=User)


@overload
def add_nin_to_user(user: User, proofing_state: NinProofingState) -> ProofingUser:
    ...


@overload
def add_nin_to_user(user: User, proofing_state: NinProofingState, user_type: type[TProofingUser]) -> TProofingUser:
    ...


def add_nin_to_user(user, proofing_state, user_type=ProofingUser):
    private_userdb = cast(UserDB[User], get_from_current_app("private_userdb", UserDB))
    proofing_user = user_type.from_user(user, private_userdb)
    # Add nin to user if not already there
    if not proofing_user.identities.nin:
        current_app.logger.info(f"Adding NIN for user {user}")
        current_app.logger.debug(f"Self asserted NIN: {proofing_state.nin.number}")
        nin_identity = NinIdentity(
            created_by=proofing_state.nin.created_by,
            created_ts=proofing_state.nin.created_ts,
            is_verified=False,  # always add a nin identity as unverified
            number=proofing_state.nin.number,
        )
        proofing_user.identities.add(nin_identity)
        save_and_sync_user(proofing_user)
    return proofing_user


def verify_nin_for_user(
    user: Union[User, ProofingUser], proofing_state: NinProofingState, proofing_log_entry: NinProofingLogElement
) -> bool:
    """
    Mark a nin on a user as verified, after logging data about the proofing to the proofing log.

    If this function is given a ProofingUser instance, the instance will be updated accordingly and
    the calling function won't need to reload the user from the central database to access the updated
    NIN element.

    :param user: A ProofingUser, or a standard User
    :param proofing_state: Proofing state for user
    :param proofing_log_entry: Proofing log entry element

    :return: Success or not
    """
    proofing_log = get_from_current_app("proofing_log", ProofingLog)
    private_userdb = cast(UserDB[User], get_from_current_app("private_userdb", UserDB))

    if isinstance(user, ProofingUser):
        proofing_user = user
    else:
        # If user is not a ProofingUser, we create a new ProofingUser instance.
        # This is deprecated usage, since it won't allow the calling function to get
        # the new NIN element without re-loading the user from the central database.
        warnings.warn("verify_nin_for_user() called with a User, not a ProofingUser", DeprecationWarning)
        proofing_user = ProofingUser.from_user(user, private_userdb)

    # add an unverified nin identity to the user if it does not exist yet
    if proofing_user.identities.nin is None:
        proofing_user = add_nin_to_user(user=proofing_user, proofing_state=proofing_state)

    # please mypy
    assert proofing_user.identities.nin is not None

    # Check if the NIN is already verified
    if proofing_user.identities.nin.is_verified:
        current_app.logger.info("User already has a verified NIN")
        current_app.logger.debug(f"NIN: {proofing_user.identities.nin.number}")
        return True

    # check if the users current nin is the same as the one just verified
    # if there is no locked nin identity or the locked nin identity matches we can replace the current nin identity
    # with the one just verified
    if proofing_user.identities.nin.number != proofing_state.nin.number:
        current_app.logger.info("users current nin does not match the nin just verified")
        current_app.logger.debug(f"{proofing_user.identities.nin.number} != {proofing_state.nin.number}")
        if (
            proofing_user.locked_identity.nin is not None
            and proofing_user.locked_identity.nin.number != proofing_state.nin.number
        ):
            raise LockedIdentityViolation("users locked nin does not match verified nin")

        # user has no locked nin identity or the user has previously verified the nin
        # replace the never verified nin with the one just verified
        proofing_user.identities.remove(ElementKey(IdentityType.NIN.value))
        nin_identity = NinIdentity(
            number=proofing_state.nin.number,
            created_ts=proofing_state.nin.created_ts,
            created_by=proofing_state.nin.created_by,
        )
        proofing_user.identities.add(nin_identity)
        current_app.logger.info("replaced users current nin with the one just verified")

    # Update users nin identity
    proofing_user.identities.nin.is_verified = True
    # Ensure matching timestamp in verification log entry, and NIN element on user
    proofing_user.identities.nin.verified_ts = proofing_log_entry.created_ts
    proofing_user.identities.nin.verified_by = proofing_state.nin.created_by
    proofing_method = IdentityProofingMethod(proofing_log_entry.proofing_method)
    proofing_user.identities.nin.proofing_method = proofing_method
    proofing_user.identities.nin.proofing_version = proofing_log_entry.proofing_version

    # Update users name
    proofing_user = set_user_names_from_nin_proofing(user=proofing_user, proofing_log_entry=proofing_log_entry)

    # If user was updated successfully continue with logging the proof and saving the user to central db
    # Send proofing data to the proofing log
    if not proofing_log.save(proofing_log_entry):
        return False
    current_app.logger.info(f"Recorded nin identity verification in the proofing log")

    save_and_sync_user(proofing_user)

    return True


def send_mail(
    subject: str,
    to_addresses: list[str],
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
    conf = get_from_current_app("conf", MailConfigMixin)

    site_name = conf.eduid_site_name
    site_url = conf.eduid_site_url

    default_context: dict[str, str] = {
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
        current_app.logger.info(f"Magic cookie parameters not present in configuration for {config.environment}")
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
    user_postal_address: FullPostalAddress
    deregistration_information: Optional[DeregistrationInformation] = None


def get_proofing_log_navet_data(nin: str) -> ProofingNavetData:
    msg_relay = get_from_current_app("msg_relay", MsgRelay)

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
