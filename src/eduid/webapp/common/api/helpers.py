import warnings
from dataclasses import dataclass
from typing import cast, overload

from flask import current_app, request

from eduid.common.config.base import EduidEnvironment, MagicCookieMixin
from eduid.common.proofing_utils import set_user_names_from_official_address
from eduid.common.rpc.exceptions import NoNavetData
from eduid.common.rpc.msg_relay import DeregisteredCauseCode, DeregistrationInformation, FullPostalAddress, MsgRelay
from eduid.userdb import NinIdentity
from eduid.userdb.element import ElementKey
from eduid.userdb.exceptions import LockedIdentityViolation
from eduid.userdb.identity import IdentityProofingMethod, IdentityType
from eduid.userdb.logs import ProofingLog
from eduid.userdb.logs.element import (
    ForeignIdProofingLogElement,
    NinEIDProofingLogElement,
    NinNavetProofingLogElement,
    NinProofingLogElement,
)
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.proofing.state import NinProofingState
from eduid.userdb.user import User
from eduid.userdb.userdb import UserDB
from eduid.webapp.common.api.utils import get_from_current_app, get_reference_nin_from_navet_data, save_and_sync_user

__author__ = "lundberg"


def set_user_names_from_nin_proofing[T: User](
    user: T,
    proofing_log_entry: NinProofingLogElement,
) -> T:
    if isinstance(proofing_log_entry, NinNavetProofingLogElement):
        user = set_user_names_from_official_address(user, proofing_log_entry)
    elif isinstance(proofing_log_entry, NinEIDProofingLogElement):
        user = set_user_names_from_nin_eid_proofing(user, proofing_log_entry)
    else:
        raise RuntimeError("No given name, surname or user postal address found in proofing log entry")
    return user


def set_user_names_from_nin_eid_proofing[T: User](user: T, proofing_log_entry: NinEIDProofingLogElement) -> T:
    user.given_name = proofing_log_entry.given_name
    user.surname = proofing_log_entry.surname
    user.legal_name = f"{proofing_log_entry.given_name} {proofing_log_entry.surname}"
    # unset chosen given name, if there was a name change it might no longer be correct
    user.chosen_given_name = None
    return user


def set_user_names_from_foreign_id[T: User](user: T, proofing_log_entry: ForeignIdProofingLogElement) -> T:
    """
    :param user: Proofing app private userdb user
    :param proofing_log_entry: Proofing log entry element

    :returns: User object
    """
    user.given_name = proofing_log_entry.given_name
    user.surname = proofing_log_entry.surname
    user.legal_name = f"{proofing_log_entry.given_name} {proofing_log_entry.surname}"
    # unset chosen given name, if there was a name change it might no longer be correct
    user.chosen_given_name = None
    return user


# Explain to mypy that if you call add_nin_to_user without a user_type, the return type will be ProofingUser
# but if you call it with a user_type the return type will be that type


@overload
def add_nin_to_user(user: User, proofing_state: NinProofingState) -> ProofingUser: ...


@overload
def add_nin_to_user[T: User](user: User, proofing_state: NinProofingState, user_type: type[T]) -> T: ...


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
            date_of_birth=proofing_state.nin.date_of_birth,
        )
        proofing_user.identities.add(nin_identity)
        save_and_sync_user(proofing_user)
    return proofing_user


def verify_nin_for_user(
    user: User | ProofingUser, proofing_state: NinProofingState, proofing_log_entry: NinProofingLogElement
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
        warnings.warn("verify_nin_for_user() called with a User, not a ProofingUser", DeprecationWarning, stacklevel=2)
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

    reference_nin = get_reference_nin_from_navet_data(proofing_state.nin.number)
    if reference_nin is not None:
        current_app.logger.debug(f"verified nin has reference_nin: {reference_nin}")

    if proofing_user.locked_identity.nin is not None and proofing_user.locked_identity.nin.number not in (
        proofing_state.nin.number,
        reference_nin,
    ):
        raise LockedIdentityViolation("users locked nin does not match verified nin or reference nin")

    # check if the users current nin is the same as the one just verified
    # if there is no locked nin identity or the locked nin identity matches we can replace the current nin identity
    # with the one just verified
    if proofing_user.identities.nin.number != proofing_state.nin.number:
        current_app.logger.info("users current nin does not match the nin just verified")
        current_app.logger.debug(f"{proofing_user.identities.nin.number} != {proofing_state.nin.number}")

        # user has no locked nin identity or the user has previously verified the nin
        # replace the never verified nin with the one just verified
        proofing_user.identities.remove(ElementKey(IdentityType.NIN.value))
        nin_identity = NinIdentity(
            number=proofing_state.nin.number,
            date_of_birth=proofing_state.nin.date_of_birth,
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

    # Replace locked nin with verified nin if it has changed in the population registry
    if (
        reference_nin is not None
        and proofing_user.locked_identity.nin is not None
        and proofing_user.locked_identity.nin.number == reference_nin
    ):
        proofing_user.replace_locked = IdentityType.NIN

    # Update users name
    proofing_user = set_user_names_from_nin_proofing(user=proofing_user, proofing_log_entry=proofing_log_entry)

    # If user was updated successfully continue with logging the proof and saving the user to central db
    # Send proofing data to the proofing log
    if not proofing_log.save(proofing_log_entry):
        return False
    current_app.logger.info("Recorded nin identity verification in the proofing log")

    save_and_sync_user(proofing_user)

    return True


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
    deregistration_information: DeregistrationInformation | None = None


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
