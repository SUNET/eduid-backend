from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import unique
from functools import cache
from typing import Any

from fido_mds.models.webauthn import AttestationFormat

from eduid.common.config.base import EduidEnvironment
from eduid.common.misc.timeutil import utc_now
from eduid.common.rpc.msg_relay import FullPostalAddress, NavetData
from eduid.common.utils import generate_password
from eduid.queue.client import init_queue_item
from eduid.queue.db.message.payload import EduidTerminationEmail
from eduid.userdb import NinIdentity
from eduid.userdb.identity import IdentityType
from eduid.userdb.logs.element import NameUpdateProofing
from eduid.userdb.security import SecurityUser
from eduid.userdb.user import User
from eduid.webapp.common.api.helpers import set_user_names_from_official_address
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.common.api.translation import get_user_locale
from eduid.webapp.security.app import current_security_app as current_app
from eduid.webapp.security.webauthn_proofing import AuthenticatorInformation, is_authenticator_mfa_approved

__author__ = "lundberg"


@unique
class SecurityMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

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
    webauthn_missing_credential_data = "security.webauthn-missing-credential-data"
    webauthn_attestation_fail = "security.webauthn-attestation-fail"
    webauthn_metadata_fail = "security.webauthn-metadata-fail"
    webauthn_registration_fail = "security.webauthn-registration-fail"
    # Status requested for unknown authn_id
    not_found = "security.not_found"
    # wrong identity type requested
    wrong_identity_type = "security.wrong-identity-type"


@dataclass
class CredentialInfo:
    key: str
    credential_type: str
    created_ts: datetime
    success_ts: datetime | None
    verified: bool = False
    description: str | None = None


def compile_credential_list(user: User) -> list[CredentialInfo]:
    """
    Make a list of a users credentials, with extra information, for returning in API responses.
    """
    credentials: list[CredentialInfo] = []
    authn_info = current_app.authninfo_db.get_authn_info(user)
    for cred_key, authn in authn_info.items():
        cred = user.credentials.find(cred_key)
        # pick up attributes not present on all types of credentials
        _description: str | None = None
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


def remove_identity_from_user(security_user: SecurityUser, identity_type: IdentityType) -> None:
    """
    Remove identity from a user and sync to central db
    """

    identity = security_user.identities.find(identity_type.value)
    if identity is None:
        return None  # no op, identity already gone

    security_user.identities.remove(identity.key)
    # Save user to private db
    current_app.private_userdb.save(security_user)
    # Ask am to sync user to central db
    current_app.logger.debug(f"Request sync for user {security_user}")
    result = current_app.am_relay.request_user_sync(security_user)
    current_app.logger.info(f"Sync result for user {security_user}: {result}")
    return None


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
    for email in user.mail_addresses.verified:
        # send a termination mail to all the users verified mail addresses
        payload = EduidTerminationEmail(
            email=email.email,
            site_name=current_app.conf.eduid_site_name,
            language=get_user_locale() or current_app.conf.default_language,
            reference=f"eppn={user.eppn},mail={email.email},ts={utc_now()}",
        )

        message = init_queue_item(app_name=current_app.conf.app_name, expires_in=timedelta(days=7), payload=payload)
        current_app.messagedb.save(message)
        current_app.logger.info(
            f"Saved termination mail queue item in queue collection {current_app.messagedb._coll_name}"
        )
        current_app.logger.debug(f"email: {email}")
        if current_app.conf.environment == EduidEnvironment.dev:
            # Debug-log the code and message in development environment
            current_app.logger.debug(f"Generating termination mail with context:\n{payload}")
        current_app.logger.info(f"Sent termination mail to user {user} to address {email}.")


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

        current_app.logger.info("Recorded verification in the proofing log")
        # Save user to private db
        current_app.private_userdb.save(security_user)
        # Ask am to sync user to central db
        current_app.logger.info("Request sync for user")
        result = current_app.am_relay.request_user_sync(security_user)
        current_app.logger.info(f"Sync result for user {security_user}: {result}")
        current_app.stats.count(name="refresh_user_data_name_updated")

    return True


@cache
def get_approved_security_keys() -> dict[str, Any]:
    # a way to reuse is_authenticator_mfa_approved() from security app
    parsed_entries: list[AuthenticatorInformation] = []
    for metadata_entry in current_app.fido_mds.metadata.entries:
        user_verification_methods = [
            detail.user_verification_method
            for detail in metadata_entry.metadata_statement.get_user_verification_details()
        ]

        # simulated to fit AuthenticatorInformation format
        attestation_format = AttestationFormat.PACKED
        if not metadata_entry.metadata_statement.attestation_types:
            attestation_format = AttestationFormat.NONE

        authenticator_info = AuthenticatorInformation(
            authenticator_id=metadata_entry.aaguid or metadata_entry.aaid,
            attestation_format=attestation_format,
            user_present=False,  # simulated to fit AuthenticatorInformation required fields
            user_verified=False,  # simulated to fit AuthenticatorInformation required fields
            status=metadata_entry.status_reports[0].status,
            last_status_change=metadata_entry.time_of_last_status_change,
            user_verification_methods=user_verification_methods,
            key_protection=metadata_entry.metadata_statement.key_protection,
            description=metadata_entry.metadata_statement.description,
            # icon=metadata_entry.metadata_statement.icon,
        )
        parsed_entries.append(authenticator_info)

    approved_keys_list: list[str] = []
    for entry in parsed_entries:
        if entry.description and is_authenticator_mfa_approved(entry):
            approved_keys_list.append(entry.description)

    # remove case-insensitive duplicates from list, while maintaining the original case
    marker = set()
    unique_approved_keys_list: list[str] = []

    for key in approved_keys_list:
        lower_case_key = key.lower()
        if lower_case_key not in marker:  # test presence
            marker.add(lower_case_key)
            unique_approved_keys_list.append(key)  # preserve original case

    # sort list - case insensitive
    return {
        "next_update": current_app.fido_mds.metadata.next_update,
        "entries": sorted(unique_approved_keys_list, key=str.casefold),
    }
