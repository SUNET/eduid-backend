from dataclasses import dataclass, field
from datetime import date, datetime, time
from enum import Enum
from uuid import UUID

from fido2.utils import websafe_decode
from fido_mds import Attestation
from fido_mds.exceptions import AttestationVerificationError, MetadataValidationError
from fido_mds.models.fido_mds import AuthenticatorStatus
from fido_mds.models.webauthn import AttestationFormat

from eduid.userdb.logs.element import FidoMetadataLogElement, WebauthnMfaCapabilityProofingLog
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.security.app import current_security_app as current_app

__author__ = "lundberg"


class OtherAuthenticatorStatus(str, Enum):
    APPLE = "APPLE"
    MAGIC_COOKIE = "MAGIC_COOKIE"


@dataclass
class AuthenticatorInformation:
    authenticator_id: UUID | str
    attestation_format: AttestationFormat
    user_present: bool
    user_verified: bool
    status: AuthenticatorStatus | OtherAuthenticatorStatus | None = field(default=None)
    last_status_change: datetime | None = field(default=None)
    icon: str | None = field(default=None)
    description: str | None = field(default=None)
    key_protection: list[str] = field(default_factory=list)
    user_verification_methods: list[str] = field(default_factory=list)


def get_authenticator_information(attestation: str, client_data: str) -> AuthenticatorInformation:
    # parse attestation object
    try:
        att = Attestation.from_base64(attestation)
    except ValueError as e:
        current_app.logger.exception("Failed to parse attestation object")
        raise e

    user_present = att.auth_data.flags.user_present
    user_verified = att.auth_data.flags.user_verified
    authenticator_id = att.aaguid or att.certificate_key_identifier

    # allow automatic tests to use any webauthn device
    if check_magic_cookie(current_app.conf):
        return AuthenticatorInformation(
            attestation_format=att.fmt,
            authenticator_id=authenticator_id,
            status=OtherAuthenticatorStatus.MAGIC_COOKIE,
            last_status_change=datetime.combine(date(year=2022, month=5, day=10), time.min),
            user_verification_methods=["magic_cookie"],
            key_protection=["magic_cookie"],
            description="Magic cookie backdoor",
            icon=None,
            user_present=user_present,
            user_verified=user_verified,
        )

    # if attestation format is None, we have no attestation and can't do any more checks
    if att.fmt == AttestationFormat.NONE:
        return AuthenticatorInformation(
            attestation_format=att.fmt,
            authenticator_id=authenticator_id,
            user_present=user_present,
            user_verified=user_verified,
        )

    # verify attestation
    try:
        current_app.fido_mds.verify_attestation(attestation=att, client_data=websafe_decode(client_data))
    except (AttestationVerificationError, MetadataValidationError) as e:
        current_app.logger.debug(f"attestation: {att}")
        current_app.logger.debug(f"client_data: {client_data}")
        current_app.logger.exception("Failed to get authenticator information")
        raise e

    # There are no metadata entries for Apple devices, just create the authenticator information
    if att.fmt is AttestationFormat.APPLE:
        return AuthenticatorInformation(
            attestation_format=att.fmt,
            authenticator_id=authenticator_id,
            status=OtherAuthenticatorStatus.APPLE,
            last_status_change=datetime.combine(date(year=2022, month=4, day=25), time.min),
            user_verification_methods=["apple"],
            key_protection=["apple"],
            description="Apple Device",
            icon=None,
            user_present=user_present,
            user_verified=user_verified,
        )

    # create authenticator information from attestation and metadata
    metadata_entry = current_app.fido_mds.get_entry(authenticator_id=authenticator_id)
    # mongodb does not support date
    last_status_change = metadata_entry.time_of_last_status_change
    user_verification_methods = [
        detail.user_verification_method for detail in metadata_entry.metadata_statement.get_user_verification_details()
    ]

    # save current metadata entry as proof if we haven't done so before
    if not current_app.fido_metadata_log.exists(
        authenticator_id=authenticator_id, last_status_change=last_status_change
    ):
        current_app.fido_metadata_log.save(
            FidoMetadataLogElement(
                created_by="security",
                authenticator_id=authenticator_id,
                last_status_change=last_status_change,
                metadata_entry=metadata_entry,
            )
        )

    return AuthenticatorInformation(
        attestation_format=att.fmt,
        authenticator_id=att.aaguid or att.certificate_key_identifier,
        status=metadata_entry.status_reports[0].status,  # latest status reports status
        last_status_change=last_status_change,
        user_verification_methods=user_verification_methods,
        key_protection=metadata_entry.metadata_statement.key_protection,
        description=metadata_entry.metadata_statement.description,
        icon=metadata_entry.metadata_statement.icon,
        user_present=user_present,
        user_verified=user_verified,
    )


def is_authenticator_mfa_approved(authenticator_info: AuthenticatorInformation) -> bool:
    """
    This is our current policy for determine if a FIDO2 authenticator can do multi-factor authentications.
    """
    # If there is no attestation we can not trust the authenticator info
    if authenticator_info.attestation_format == AttestationFormat.NONE:
        return False

    # Our current policy is that Apple is capable of mfa
    if authenticator_info.status is OtherAuthenticatorStatus.APPLE:
        current_app.logger.debug("apple device is mfa capable")
        return True

    # check status in metadata and disallow uncertified and incident statuses
    if authenticator_info.status not in current_app.conf.webauthn_allowed_status:
        current_app.logger.debug(f"status {authenticator_info.status} is not mfa capable")
        return False

    # true if the authenticator supports any of the user verification methods we allow
    is_accepted_user_verification = any(
        [
            method
            for method in authenticator_info.user_verification_methods
            if method in current_app.conf.webauthn_allowed_user_verification_methods
        ]
    )
    # a typical token has key protection ["hardware"] or ["hardware", "tee"] but some also support software, so
    # we have to check that all key protections supported is in our allow list
    is_accepted_key_protection = all(
        [
            protection
            for protection in authenticator_info.key_protection
            if protection in current_app.conf.webauthn_allowed_key_protection
        ]
    )
    current_app.logger.debug(f"is_accepted_user_verification: {is_accepted_user_verification}")
    current_app.logger.debug(f"is_accepted_key_protection: {is_accepted_key_protection}")
    if is_accepted_user_verification and is_accepted_key_protection:
        return True
    return False


def save_webauthn_proofing_log(eppn: str, authenticator_info: AuthenticatorInformation) -> bool:
    user_verification_methods_match = set(authenticator_info.user_verification_methods) & set(
        current_app.conf.webauthn_allowed_user_verification_methods
    )
    current_app.logger.debug(f"user verifications methods that match config: {user_verification_methods_match}")
    key_protection_match = set(authenticator_info.key_protection) & set(
        current_app.conf.webauthn_allowed_key_protection
    )
    current_app.logger.debug(f"user verifications methods that match config: {user_verification_methods_match}")

    proofing_element = WebauthnMfaCapabilityProofingLog(
        created_by=current_app.conf.app_name,
        eppn=eppn,
        proofing_version=current_app.conf.webauthn_proofing_version,
        proofing_method=current_app.conf.webauthn_proofing_method,
        authenticator_id=authenticator_info.authenticator_id,
        attestation_format=authenticator_info.attestation_format,
        user_verification_methods=list(user_verification_methods_match),
        key_protection=list(key_protection_match),
    )
    current_app.logger.debug(f"webauthn mfa capability proofing element: {proofing_element}")
    return current_app.proofing_log.save(proofing_element)
