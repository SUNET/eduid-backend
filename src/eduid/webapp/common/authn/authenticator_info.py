"""Identify and classify WebAuthn/U2F credentials from the data we already store.

Everything here is derived on read: nothing is written to the user document. The input is the stored credential
(its AAGUID inside `credential_data`, the `authenticator_id` and `attestation_format` fields, the legacy U2F
`attest_cert`) and the FIDO Metadata Service (MDS) entry for the authenticator, if there is one.

The result is codes and identifiers only (`KeyKind`, `Discoverable`, ids, and the name and icon MDS publishes for
the authenticator); texts for the user are the frontend's business.
"""

import base64
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import UUID

from cryptography import x509
from fido2.webauthn import AttestedCredentialData, AuthenticatorAttachment
from fido_mds.models.webauthn import AttestationFormat

from eduid.userdb.credentials import Credential, Webauthn
from eduid.userdb.credentials.fido import U2F

__author__ = "ylle"

logger = logging.getLogger(__name__)

ZERO_AAGUID = UUID(int=0)
# Windows Hello (hardware, software and VBS hardware). To our knowledge it creates a discoverable credential only
# when asked to require one, so it is not assumed to be discoverable like other platform authenticators.
WINDOWS_HELLO_AAGUIDS = frozenset(
    {
        UUID("08987058-cadc-4b81-b6e1-30de50dcbe96"),
        UUID("6028b017-b1d4-4c02-b4b3-afcdafc96bb2"),
        UUID("9ddd1817-af5a-4672-a2b9-3e3dd95000a9"),
    }
)
# A certificate key identifier (SHA-1 of the public key) as published by MDS: 40 hex characters
_KEY_IDENTIFIER = re.compile(r"[0-9a-f]{40}")


class KeyKind(StrEnum):
    SECURITY_KEY = "security_key"
    PASSKEY = "passkey"
    UNKNOWN = "unknown"


class Discoverable(StrEnum):
    """Whether the credential is a discoverable one (usable without typing a username)."""

    YES = "yes"
    LIKELY = "likely"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class MdsInfo:
    """What MDS says about an authenticator. The name and icon are MDS' own text, passed through untouched."""

    name: str | None
    icon: str | None
    key_protection: tuple[str, ...]
    attachment_hint: tuple[str, ...]


@dataclass(frozen=True)
class AuthenticatorClassification:
    authenticator_id: UUID | str | None
    kind: KeyKind
    discoverable: Discoverable
    name: str | None = None
    icon: str | None = None


class _MetadataStore(Protocol):
    """The part of fido_mds.FidoMetadataStore that is used here (so tests can use a small fake)."""

    def get_entry(self, authenticator_id: UUID | str) -> object | None: ...


def normalize_authenticator_id(value: object) -> UUID | str | None:
    """Make a stored authenticator id usable for an MDS lookup.

    The stored value is a UUID (an AAGUID), the same UUID as a string (both forms exist in the data: UUIDs are
    stored as BSON binary and as strings), or a certificate key identifier (40 hex characters). MDS' get_entry()
    treats a string as a certificate key identifier, so an AAGUID that came back as a string must become a UUID.
    The all-zero AAGUID means "not reported" and is not an id.
    """
    if value is None:
        return None
    if isinstance(value, UUID):
        return None if value == ZERO_AAGUID else value
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if _KEY_IDENTIFIER.fullmatch(candidate):
        return candidate
    try:
        aaguid = UUID(candidate)
    except ValueError:
        return None
    return None if aaguid == ZERO_AAGUID else aaguid


def aaguid_from_credential_data(credential_data: str | None) -> UUID | None:
    """The AAGUID inside a stored `credential_data` (base64 of an AttestedCredentialData), if it is not zero."""
    if not credential_data:
        return None
    try:
        raw = base64.urlsafe_b64decode(credential_data.encode("ascii") + b"=" * (-len(credential_data) % 4))
        acd, _rest = AttestedCredentialData.unpack_from(raw)
        aaguid = UUID(bytes=bytes(acd.aaguid))
    except (ValueError, IndexError):  # includes binascii.Error and UnicodeEncodeError
        logger.debug("could not read an AAGUID from credential_data")
        return None
    return None if aaguid == ZERO_AAGUID else aaguid


def key_identifier_from_certificate(attest_cert: str | None) -> str | None:
    """The MDS certificate key identifier of a (legacy U2F) attestation certificate.

    Computed like fido_mds does for `fido-u2f` attestation: the SHA-1 based key identifier of the certificate's
    public key, as hex. The stored value is a PEM certificate; a bare base64 DER certificate is accepted too.
    """
    if not attest_cert or not attest_cert.strip():
        return None
    text = attest_cert.strip()
    try:
        if text.startswith("-----BEGIN"):
            cert = x509.load_pem_x509_certificate(text.encode("ascii"))
        else:
            cert = x509.load_der_x509_certificate(base64.b64decode(text, validate=True))
        return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest.hex()
    except (ValueError, TypeError):  # includes binascii.Error and UnicodeEncodeError
        logger.debug("could not read a certificate key identifier from attest_cert")
        return None


def authenticator_id_for(credential: Credential) -> UUID | str | None:
    """Identify the authenticator of a credential. The first hit wins:

    1. the stored `authenticator_id`
    2. the AAGUID inside `credential_data`
    3. for a legacy U2F credential, the key identifier of its `attest_cert`
    """
    if isinstance(credential, Webauthn):
        return normalize_authenticator_id(credential.authenticator_id) or aaguid_from_credential_data(
            credential.credential_data
        )
    if isinstance(credential, U2F):
        return key_identifier_from_certificate(credential.attest_cert)
    return None


class AuthenticatorInfoResolver:
    """Looks up MDS entries (with a cache that includes misses) and classifies credentials."""

    def __init__(self, store: _MetadataStore) -> None:
        self._store = store
        self._cache: dict[UUID | str, MdsInfo | None] = {}

    def mds_info(self, authenticator_id: UUID | str | None) -> MdsInfo | None:
        if authenticator_id is None:
            return None
        if authenticator_id in self._cache:
            return self._cache[authenticator_id]
        info: MdsInfo | None = None
        try:
            entry = self._store.get_entry(authenticator_id)
            statement = getattr(entry, "metadata_statement", None)
            if statement is not None:
                info = MdsInfo(
                    name=statement.description or None,
                    icon=statement.icon or None,
                    key_protection=tuple(str(x) for x in statement.key_protection or ()),
                    attachment_hint=tuple(str(x) for x in statement.attachment_hint or ()),
                )
        except Exception:  # an odd entry or a store problem must not break listing the user's keys
            logger.exception(f"MDS lookup failed for authenticator {authenticator_id}")
            info = None
        self._cache[authenticator_id] = info
        return info

    def classify(
        self, credential: Credential, *, resident_key_cutoff: datetime | None = None
    ) -> AuthenticatorClassification:
        """Classify a credential.

        `resident_key_cutoff` is when the registration flow started asking for discoverable credentials; it is
        only used to guess for hardware keys and Windows Hello, and without it those stay `unknown`.
        """
        authenticator_id = authenticator_id_for(credential)
        mds = self.mds_info(authenticator_id)
        kind = _kind(credential, mds)
        return AuthenticatorClassification(
            authenticator_id=authenticator_id,
            kind=kind,
            discoverable=_discoverable(
                credential, kind, _is_windows_hello(credential, authenticator_id, mds), resident_key_cutoff
            ),
            name=mds.name if mds else None,
            icon=mds.icon if mds else None,
        )


def _kind(credential: Credential, mds: MdsInfo | None) -> KeyKind:
    if isinstance(credential, U2F):
        return KeyKind.SECURITY_KEY
    if not isinstance(credential, Webauthn):
        return KeyKind.UNKNOWN
    if credential.attestation_format is AttestationFormat.FIDO_U2F:
        return KeyKind.SECURITY_KEY
    # MDS' attachment hint tells a security key from a platform authenticator; its key protection does not
    # (Windows Hello and Android report hardware protection too).
    if mds is not None:
        if "external" in mds.attachment_hint:
            return KeyKind.SECURITY_KEY
        if "internal" in mds.attachment_hint:
            return KeyKind.PASSKEY
    if credential.attestation_format is AttestationFormat.APPLE:
        return KeyKind.PASSKEY
    # `platform` is only stored when the user chose "this device"; the load-time default is `cross-platform`,
    # so a stored `cross-platform` says nothing.
    if credential.authenticator == AuthenticatorAttachment.PLATFORM:
        return KeyKind.PASSKEY
    return KeyKind.UNKNOWN


def _is_windows_hello(credential: Credential, authenticator_id: UUID | str | None, mds: MdsInfo | None) -> bool:
    """Windows Hello by what identifies it, not by the attestation format: old credentials have none stored, and
    Windows Hello can also register with `none` attestation."""
    if isinstance(credential, Webauthn) and credential.attestation_format is AttestationFormat.TPM:
        return True
    if authenticator_id in WINDOWS_HELLO_AAGUIDS:
        return True
    return bool(mds and mds.name and mds.name.startswith("Windows Hello"))


def _discoverable(credential: Credential, kind: KeyKind, windows_hello: bool, cutoff: datetime | None) -> Discoverable:
    if isinstance(credential, U2F):
        return Discoverable.NO
    if not isinstance(credential, Webauthn):
        return Discoverable.UNKNOWN
    if credential.attestation_format is AttestationFormat.FIDO_U2F:
        return Discoverable.NO
    # Platform and synced passkeys are discoverable. Windows Hello is not assumed to be (see WINDOWS_HELLO_AAGUIDS).
    if kind is KeyKind.PASSKEY and not windows_hello:
        return Discoverable.YES
    if kind is KeyKind.SECURITY_KEY or windows_hello:
        return _by_cutoff(credential.created_ts, cutoff)
    return Discoverable.UNKNOWN


def _by_cutoff(created_ts: datetime, cutoff: datetime | None) -> Discoverable:
    if cutoff is None:
        return Discoverable.UNKNOWN
    if created_ts.tzinfo is None:
        created_ts = created_ts.replace(tzinfo=UTC)
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=UTC)
    return Discoverable.LIKELY if created_ts >= cutoff else Discoverable.NO
