"""Shared WebAuthn helper functions for registration and proofing."""

import base64
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, time
from enum import StrEnum
from uuid import UUID

from fido2.server import Fido2Server, PublicKeyCredentialRpEntity
from fido2.webauthn import AttestationConveyancePreference, AttestationObject, AttestedCredentialData
from fido_mds import Attestation, FidoMetadataStore
from fido_mds.exceptions import AttestationVerificationError, MetadataValidationError
from fido_mds.models.fido_mds import AuthenticatorStatus
from fido_mds.models.webauthn import AttestationFormat

from eduid.userdb.credentials import Webauthn
from eduid.userdb.credentials.fido import U2F, FidoCredential
from eduid.userdb.logs.db import FidoMetadataLog, ProofingLog
from eduid.userdb.logs.element import FidoMetadataLogElement, WebauthnMfaCapabilityProofingLog

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class OtherAuthenticatorStatus(StrEnum):
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


def get_webauthn_server(
    rp_id: str, rp_name: str, attestation: AttestationConveyancePreference | None = None
) -> Fido2Server:
    rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
    return Fido2Server(rp, attestation=attestation)


def make_credentials(creds: Sequence[FidoCredential]) -> list[AttestedCredentialData]:
    credentials = []
    for cred in creds:
        if isinstance(cred, Webauthn):
            cred_data = base64.urlsafe_b64decode(cred.credential_data.encode("ascii"))
            credential_data, rest = AttestedCredentialData.unpack_from(cred_data)
            if rest:
                continue
        elif isinstance(cred, U2F):
            # cred is of type U2F (legacy registration)
            credential_data = AttestedCredentialData.from_ctap1(
                cred.keyhandle.encode("ascii"), cred.public_key.encode("ascii")
            )
        else:
            raise ValueError(f"Unknown credential {cred!r}")
        credentials.append(credential_data)
    return credentials


def get_authenticator_information(
    attestation: AttestationObject,
    client_data: bytes,
    fido_mds: FidoMetadataStore,
    fido_metadata_log: FidoMetadataLog,
    app_name: str,
    is_backdoor: bool = False,
) -> AuthenticatorInformation:
    # parse attestation object
    try:
        att = Attestation.from_attestation_object(attestation)
    except ValueError as e:
        logger.exception("Failed to parse attestation object")
        raise e

    user_present = att.auth_data.flags.user_present
    user_verified = att.auth_data.flags.user_verified
    authenticator_id = att.aaguid or att.certificate_key_identifier

    # allow automatic tests to use any webauthn device
    if is_backdoor:
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
        fido_mds.verify_attestation(attestation=att, client_data=client_data)
    except AttestationVerificationError as e:
        logger.debug(f"attestation: {att}")
        logger.debug(f"client_data: {client_data!r}")
        logger.exception("Failed to get authenticator information")
        raise e
    except MetadataValidationError:
        logger.debug(f"attestation: {att}")
        logger.debug(f"client_data: {client_data!r}")
        logger.exception("Failed to get authenticator information from metadata, continuing without metadata")
        # Continue even if the security key _should_ be found and validated with metadata as we have seen security keys
        # in the wild that fails
        return AuthenticatorInformation(
            attestation_format=AttestationFormat.NONE,
            authenticator_id=authenticator_id,
            user_present=user_present,
            user_verified=user_verified,
        )

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
    metadata_entry = fido_mds.get_entry(authenticator_id=authenticator_id)
    # mongodb does not support date
    last_status_change = metadata_entry.time_of_last_status_change
    user_verification_methods = [
        detail.user_verification_method for detail in metadata_entry.metadata_statement.get_user_verification_details()
    ]

    # save current metadata entry as proof if we haven't done so before
    if not fido_metadata_log.exists(authenticator_id=authenticator_id, last_status_change=last_status_change):
        fido_metadata_log.save(
            FidoMetadataLogElement(
                created_by=app_name,
                authenticator_id=authenticator_id,
                last_status_change=last_status_change,
                metadata_entry=metadata_entry,
            )
        )

    return AuthenticatorInformation(
        attestation_format=att.fmt,
        authenticator_id=att.aaguid or att.certificate_key_identifier,
        status=max(
            metadata_entry.status_reports, key=lambda sr: sr.effective_date
        ).status,  # latest status reports status
        last_status_change=last_status_change,
        user_verification_methods=user_verification_methods,
        key_protection=metadata_entry.metadata_statement.key_protection,
        description=metadata_entry.metadata_statement.description,
        icon=metadata_entry.metadata_statement.icon,
        user_present=user_present,
        user_verified=user_verified,
    )


def is_authenticator_mfa_approved(
    authenticator_info: AuthenticatorInformation,
    disallowed_status: Sequence[AuthenticatorStatus] = (),
) -> bool:
    """
    This is our current policy for determine if a FIDO2 authenticator can do multi-factor authentications.
    """
    if authenticator_info.user_verified:
        logger.info(
            f"AttestationFormat {authenticator_info.attestation_format}: user verified - authenticator is mfa capable"
        )

        # check status in metadata (if any) and disallow incident statuses
        if authenticator_info.status and authenticator_info.status in disallowed_status:
            logger.debug(f"status {authenticator_info.status} is not mfa capable")
            return False

        return True
    logger.info(
        f"AttestationFormat {authenticator_info.attestation_format}: user NOT verified - authenticator is not mfa "
        f"capable"
    )
    return False


def save_webauthn_proofing_log(
    eppn: str,
    authenticator_info: AuthenticatorInformation,
    proofing_log: ProofingLog,
    app_name: str,
    proofing_version: str,
    proofing_method: str,
) -> bool:
    proofing_element = WebauthnMfaCapabilityProofingLog(
        created_by=app_name,
        eppn=eppn,
        proofing_version=proofing_version,
        proofing_method=proofing_method,
        authenticator_id=authenticator_info.authenticator_id,
        attestation_format=authenticator_info.attestation_format,
        user_verification_methods=authenticator_info.user_verification_methods,
        key_protection=authenticator_info.key_protection,
    )
    logger.debug(f"webauthn mfa capability proofing element: {proofing_element}")
    return proofing_log.save(proofing_element)
