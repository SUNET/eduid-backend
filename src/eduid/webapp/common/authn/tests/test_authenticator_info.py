import base64
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorAttachment
from fido_mds.models.webauthn import AttestationFormat

from eduid.userdb.credentials import Webauthn
from eduid.userdb.credentials.fido import U2F
from eduid.webapp.common.authn.authenticator_info import (
    ZERO_AAGUID,
    AuthenticatorInfoResolver,
    Discoverable,
    KeyKind,
    aaguid_from_credential_data,
    authenticator_id_for,
    key_identifier_from_certificate,
    normalize_authenticator_id,
)

YUBIKEY = UUID("2fc0579f-8113-47ea-b116-bb5a8db9202a")
WINDOWS_HELLO = UUID("08987058-cadc-4b81-b6e1-30de50dcbe96")
ANDROID = UUID("b93fd961-f2e6-462f-b122-82002247de78")
PASSWORD_MANAGER = UUID("d548826e-79b4-db40-a3d8-11116f7e8349")  # not in MDS
CUTOFF = datetime(2025, 10, 14, tzinfo=UTC)
BEFORE = CUTOFF - timedelta(days=30)
AFTER = CUTOFF + timedelta(days=30)


def credential_data(aaguid: UUID) -> str:
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    cose_key = ES256.from_cryptography_key(public_key)  # type: ignore[no-untyped-call]
    acd = AttestedCredentialData.create(aaguid.bytes, os.urandom(32), cose_key)
    return base64.urlsafe_b64encode(bytes(acd)).decode("ascii")


def webauthn(
    aaguid: UUID = ZERO_AAGUID,
    authenticator_id: UUID | str | None = None,
    attestation_format: AttestationFormat | None = None,
    authenticator: AuthenticatorAttachment = AuthenticatorAttachment.CROSS_PLATFORM,
    created_ts: datetime = AFTER,
) -> Webauthn:
    return Webauthn(
        keyhandle=base64.urlsafe_b64encode(os.urandom(16)).decode("ascii"),
        credential_data=credential_data(aaguid),
        app_id="eduid.docker",
        authenticator=authenticator,
        authenticator_id=authenticator_id,
        attestation_format=attestation_format,
        created_ts=created_ts,
    )


def certificate() -> tuple[str, str]:
    """A self-signed certificate as PEM, and the key identifier it should give."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test attestation")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return pem, x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest.hex()


def u2f(attest_cert: str | None) -> U2F:
    return U2F(
        keyhandle="a-key-handle",
        app_id="https://eduid.docker",
        version="U2F_V2",
        public_key="a-public-key",
        attest_cert=attest_cert,
    )


class FakeStore:
    """Stands in for FidoMetadataStore: answers for the ids it was given and remembers what it was asked."""

    def __init__(self, entries: dict[UUID | str, dict[str, Any]]) -> None:
        self.entries = entries
        self.asked: list[UUID | str] = []

    def get_entry(self, authenticator_id: UUID | str) -> SimpleNamespace | None:
        self.asked.append(authenticator_id)
        data = self.entries.get(authenticator_id)
        if data is None:
            return None
        return SimpleNamespace(metadata_statement=SimpleNamespace(**data))


def external(name: str) -> dict[str, Any]:
    return {
        "description": name,
        "icon": "data:image/png;base64,AAAA",
        "key_protection": ["hardware", "secure_element"],
        "attachment_hint": ["external", "wired", "nfc"],
    }


def internal(name: str) -> dict[str, Any]:
    return {"description": name, "icon": None, "key_protection": ["hardware", "tee"], "attachment_hint": ["internal"]}


@pytest.fixture
def store() -> FakeStore:
    return FakeStore(
        {
            YUBIKEY: external("YubiKey 5 Series with NFC"),
            WINDOWS_HELLO: internal("Windows Hello Hardware Authenticator"),
            ANDROID: internal("Android Authenticator"),
        }
    )


@pytest.fixture
def resolver(store: FakeStore) -> AuthenticatorInfoResolver:
    return AuthenticatorInfoResolver(store)


# --- normalize_authenticator_id ---------------------------------------------------------------------------------


def test_normalize_keeps_a_uuid() -> None:
    assert normalize_authenticator_id(YUBIKEY) == YUBIKEY


def test_normalize_turns_a_uuid_string_into_a_uuid() -> None:
    # stored as a string in part of the data; as a string MDS would treat it as a certificate key identifier
    assert normalize_authenticator_id(str(YUBIKEY).upper()) == YUBIKEY


def test_normalize_keeps_a_key_identifier_as_a_lower_case_string() -> None:
    assert normalize_authenticator_id("D002F4C0A88A7C27D5201C6A51A0E0546B6D8F75") == (
        "d002f4c0a88a7c27d5201c6a51a0e0546b6d8f75"
    )


@pytest.mark.parametrize("value", [None, "", "  ", "not an id", 17, b"\x00" * 16, ZERO_AAGUID, str(ZERO_AAGUID)])
def test_normalize_gives_none_for_what_is_not_an_id(value: object) -> None:
    assert normalize_authenticator_id(value) is None


# --- aaguid_from_credential_data --------------------------------------------------------------------------------


def test_aaguid_is_read_from_credential_data() -> None:
    assert aaguid_from_credential_data(credential_data(YUBIKEY)) == YUBIKEY


def test_aaguid_tolerates_missing_base64_padding() -> None:
    assert aaguid_from_credential_data(credential_data(YUBIKEY).rstrip("=")) == YUBIKEY


@pytest.mark.parametrize("value", [None, "", "!!!", "AAAA"])
def test_aaguid_is_none_for_unreadable_data(value: str | None) -> None:
    assert aaguid_from_credential_data(value) is None


def test_zero_aaguid_is_not_an_id() -> None:
    assert aaguid_from_credential_data(credential_data(ZERO_AAGUID)) is None


# --- key_identifier_from_certificate ----------------------------------------------------------------------------


def test_key_identifier_from_a_pem_certificate() -> None:
    pem, expected = certificate()
    assert key_identifier_from_certificate(pem) == expected


def test_key_identifier_from_a_bare_base64_der_certificate() -> None:
    pem, expected = certificate()
    der = x509.load_pem_x509_certificate(pem.encode("ascii")).public_bytes(serialization.Encoding.DER)
    assert key_identifier_from_certificate(base64.b64encode(der).decode("ascii")) == expected


@pytest.mark.parametrize(
    "value", [None, "", "   ", "cert", "-----BEGIN CERTIFICATE-----\nnonsense\n-----END CERTIFICATE-----"]
)
def test_key_identifier_is_none_for_unusable_certificates(value: str | None) -> None:
    assert key_identifier_from_certificate(value) is None


# --- authenticator_id_for ---------------------------------------------------------------------------------------


def test_stored_authenticator_id_wins_over_credential_data() -> None:
    credential = webauthn(aaguid=ANDROID, authenticator_id=YUBIKEY)
    assert authenticator_id_for(credential) == YUBIKEY


def test_a_stored_uuid_string_is_returned_as_a_uuid() -> None:
    assert authenticator_id_for(webauthn(authenticator_id=str(YUBIKEY))) == YUBIKEY


def test_a_stored_zero_aaguid_falls_back_to_credential_data() -> None:
    assert authenticator_id_for(webauthn(aaguid=YUBIKEY, authenticator_id=ZERO_AAGUID)) == YUBIKEY
    assert authenticator_id_for(webauthn(aaguid=YUBIKEY, authenticator_id=str(ZERO_AAGUID))) == YUBIKEY


def test_a_credential_without_stored_id_is_identified_from_credential_data() -> None:
    assert authenticator_id_for(webauthn(aaguid=YUBIKEY)) == YUBIKEY


def test_nothing_to_identify_gives_none() -> None:
    assert authenticator_id_for(webauthn(aaguid=ZERO_AAGUID)) is None


def test_a_stored_key_identifier_is_returned_as_a_string() -> None:
    key_identifier = "52d62663f0c8f4d623f462efff4500789bc9e42a"
    credential = webauthn(authenticator_id=key_identifier, attestation_format=AttestationFormat.FIDO_U2F)
    assert authenticator_id_for(credential) == key_identifier


def test_u2f_is_identified_from_its_certificate() -> None:
    pem, expected = certificate()
    assert authenticator_id_for(u2f(pem)) == expected
    assert authenticator_id_for(u2f("")) is None


# --- the MDS lookup ---------------------------------------------------------------------------------------------


def test_mds_is_asked_with_a_uuid_even_when_the_id_was_stored_as_a_string(
    resolver: AuthenticatorInfoResolver, store: FakeStore
) -> None:
    classification = resolver.classify(webauthn(authenticator_id=str(YUBIKEY)))
    assert classification.name == "YubiKey 5 Series with NFC"
    assert store.asked == [YUBIKEY]
    assert isinstance(store.asked[0], UUID)


def test_hits_and_misses_are_cached(resolver: AuthenticatorInfoResolver, store: FakeStore) -> None:
    for _ in range(3):
        resolver.classify(webauthn(aaguid=YUBIKEY))
        resolver.classify(webauthn(aaguid=PASSWORD_MANAGER))
    assert sorted(store.asked, key=str) == sorted([YUBIKEY, PASSWORD_MANAGER], key=str)


def test_a_failing_lookup_gives_no_information_and_is_not_repeated() -> None:
    class BrokenStore:
        calls = 0

        def get_entry(self, authenticator_id: UUID | str) -> object:
            self.calls += 1
            raise RuntimeError("boom")

    store = BrokenStore()
    resolver = AuthenticatorInfoResolver(store)
    for _ in range(2):
        classification = resolver.classify(webauthn(aaguid=YUBIKEY, authenticator=AuthenticatorAttachment.PLATFORM))
        assert classification.name is None
        assert classification.kind is KeyKind.PASSKEY  # still classified from what is stored
    assert store.calls == 1


# --- classify ---------------------------------------------------------------------------------------------------


def test_a_security_key_known_to_mds(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(aaguid=YUBIKEY, authenticator_id=YUBIKEY, attestation_format=AttestationFormat.PACKED)
    classification = resolver.classify(credential, resident_key_cutoff=CUTOFF)
    assert classification.authenticator_id == YUBIKEY
    assert classification.kind is KeyKind.SECURITY_KEY
    assert classification.name == "YubiKey 5 Series with NFC"
    assert classification.icon == "data:image/png;base64,AAAA"
    assert classification.discoverable is Discoverable.LIKELY


def test_a_hardware_key_registered_before_the_cutoff_is_not_discoverable(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(aaguid=YUBIKEY, attestation_format=AttestationFormat.PACKED, created_ts=BEFORE)
    assert resolver.classify(credential, resident_key_cutoff=CUTOFF).discoverable is Discoverable.NO


def test_a_hardware_key_is_unknown_without_a_cutoff(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(aaguid=YUBIKEY, attestation_format=AttestationFormat.PACKED)
    classification = resolver.classify(credential)
    assert classification.kind is KeyKind.SECURITY_KEY
    assert classification.discoverable is Discoverable.UNKNOWN


def test_a_naive_cutoff_is_read_as_utc(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(aaguid=YUBIKEY, created_ts=AFTER)
    assert resolver.classify(credential, resident_key_cutoff=CUTOFF.replace(tzinfo=None)).discoverable is (
        Discoverable.LIKELY
    )


def test_windows_hello_is_a_passkey_that_is_not_known_to_be_discoverable(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(
        aaguid=WINDOWS_HELLO,
        attestation_format=AttestationFormat.TPM,
        authenticator=AuthenticatorAttachment.PLATFORM,
        created_ts=BEFORE,
    )
    classification = resolver.classify(credential, resident_key_cutoff=CUTOFF)
    assert classification.kind is KeyKind.PASSKEY
    assert classification.name == "Windows Hello Hardware Authenticator"
    assert classification.discoverable is Discoverable.UNKNOWN
    assert resolver.classify(credential).discoverable is Discoverable.UNKNOWN


def test_an_android_authenticator_is_a_passkey_that_is_not_known_to_be_discoverable(
    resolver: AuthenticatorInfoResolver,
) -> None:
    credential = webauthn(
        aaguid=ANDROID,
        attestation_format=AttestationFormat.ANDROID_SAFETYNET,
        authenticator=AuthenticatorAttachment.PLATFORM,
    )
    classification = resolver.classify(credential)
    assert classification.kind is KeyKind.PASSKEY
    assert classification.discoverable is Discoverable.UNKNOWN


def test_mds_wins_over_the_stored_attachment(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(aaguid=YUBIKEY, authenticator=AuthenticatorAttachment.PLATFORM)
    assert resolver.classify(credential).kind is KeyKind.SECURITY_KEY


def test_a_password_manager_passkey_is_a_passkey_through_the_stored_platform_attachment(
    resolver: AuthenticatorInfoResolver,
) -> None:
    credential = webauthn(
        aaguid=PASSWORD_MANAGER,
        authenticator_id=PASSWORD_MANAGER,
        attestation_format=AttestationFormat.NONE,
        authenticator=AuthenticatorAttachment.PLATFORM,
    )
    classification = resolver.classify(credential)
    assert classification.authenticator_id == PASSWORD_MANAGER
    assert classification.name is None  # not in MDS: the frontend names it
    assert classification.kind is KeyKind.PASSKEY
    assert classification.discoverable is Discoverable.UNKNOWN


def test_a_stored_cross_platform_attachment_says_nothing(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(aaguid=PASSWORD_MANAGER, attestation_format=AttestationFormat.NONE)
    classification = resolver.classify(credential)
    assert classification.kind is KeyKind.UNKNOWN
    assert classification.discoverable is Discoverable.UNKNOWN


def test_apple_attestation_is_a_passkey(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(aaguid=PASSWORD_MANAGER, attestation_format=AttestationFormat.APPLE)
    classification = resolver.classify(credential)
    assert classification.kind is KeyKind.PASSKEY
    assert classification.discoverable is Discoverable.UNKNOWN


def test_a_zero_aaguid_is_not_evidence_of_a_security_key(resolver: AuthenticatorInfoResolver) -> None:
    # `none` attestation with a zero AAGUID is what privacy-preserving platform passkeys look like
    credential = webauthn(aaguid=ZERO_AAGUID, authenticator_id=ZERO_AAGUID, attestation_format=AttestationFormat.NONE)
    classification = resolver.classify(credential)
    assert classification.authenticator_id is None
    assert classification.kind is KeyKind.UNKNOWN


def test_a_zero_aaguid_stored_as_platform_is_a_passkey(resolver: AuthenticatorInfoResolver) -> None:
    credential = webauthn(
        aaguid=ZERO_AAGUID,
        authenticator_id=str(ZERO_AAGUID),
        attestation_format=AttestationFormat.NONE,
        authenticator=AuthenticatorAttachment.PLATFORM,
    )
    assert resolver.classify(credential).kind is KeyKind.PASSKEY


def test_an_old_credential_without_id_or_format_is_identified_from_its_credential_data(
    resolver: AuthenticatorInfoResolver,
) -> None:
    classification = resolver.classify(webauthn(aaguid=YUBIKEY))
    assert classification.authenticator_id == YUBIKEY
    assert classification.name == "YubiKey 5 Series with NFC"


def test_u2f_compatible_webauthn_is_a_security_key_that_is_not_discoverable() -> None:
    key_identifier = "52d62663f0c8f4d623f462efff4500789bc9e42a"
    resolver = AuthenticatorInfoResolver(FakeStore({key_identifier: external("YubiKey 4")}))
    credential = webauthn(authenticator_id=key_identifier, attestation_format=AttestationFormat.FIDO_U2F)
    classification = resolver.classify(credential, resident_key_cutoff=CUTOFF)
    assert classification.kind is KeyKind.SECURITY_KEY
    assert classification.discoverable is Discoverable.NO
    assert classification.name == "YubiKey 4"


def test_legacy_u2f_is_a_security_key_named_through_its_certificate() -> None:
    pem, key_identifier = certificate()
    resolver = AuthenticatorInfoResolver(FakeStore({key_identifier: external("YubiKey NEO")}))
    classification = resolver.classify(u2f(pem), resident_key_cutoff=CUTOFF)
    assert classification.authenticator_id == key_identifier
    assert classification.kind is KeyKind.SECURITY_KEY
    assert classification.discoverable is Discoverable.NO
    assert classification.name == "YubiKey NEO"


def test_legacy_u2f_with_a_useless_certificate_is_still_a_security_key(resolver: AuthenticatorInfoResolver) -> None:
    classification = resolver.classify(u2f(""))
    assert classification.authenticator_id is None
    assert classification.kind is KeyKind.SECURITY_KEY
    assert classification.name is None


@pytest.mark.parametrize("attestation_format", [None, AttestationFormat.NONE, AttestationFormat.TPM])
def test_windows_hello_is_a_passkey_whatever_the_stored_attestation_format(
    resolver: AuthenticatorInfoResolver, attestation_format: AttestationFormat | None
) -> None:
    def credential(created_ts: datetime) -> Webauthn:
        return webauthn(
            aaguid=WINDOWS_HELLO,
            attestation_format=attestation_format,
            authenticator=AuthenticatorAttachment.PLATFORM,
            created_ts=created_ts,
        )

    assert resolver.classify(credential(BEFORE)).kind is KeyKind.PASSKEY
    assert resolver.classify(credential(BEFORE), resident_key_cutoff=CUTOFF).discoverable is Discoverable.UNKNOWN
    assert resolver.classify(credential(AFTER), resident_key_cutoff=CUTOFF).discoverable is Discoverable.LIKELY
    assert resolver.classify(credential(AFTER)).discoverable is Discoverable.UNKNOWN


@pytest.mark.parametrize("attachment", [AuthenticatorAttachment.PLATFORM, AuthenticatorAttachment.CROSS_PLATFORM])
def test_windows_hello_is_a_passkey_when_mds_does_not_know_it_whatever_the_stored_attachment(
    attachment: AuthenticatorAttachment,
) -> None:
    # `cross-platform` is also what a credential without a stored attachment gets when it is loaded
    resolver = AuthenticatorInfoResolver(FakeStore({}))
    credential = webauthn(aaguid=WINDOWS_HELLO, authenticator=attachment, created_ts=AFTER)
    classification = resolver.classify(credential, resident_key_cutoff=CUTOFF)
    assert classification.name is None
    assert classification.kind is KeyKind.PASSKEY
    assert classification.discoverable is Discoverable.LIKELY


def test_windows_hello_is_a_passkey_when_the_mds_lookup_fails() -> None:
    class BrokenStore:
        def get_entry(self, authenticator_id: UUID | str) -> object:
            raise RuntimeError("boom")

    resolver = AuthenticatorInfoResolver(BrokenStore())
    classification = resolver.classify(webauthn(aaguid=WINDOWS_HELLO))
    assert classification.kind is KeyKind.PASSKEY


def test_windows_hello_is_known_by_the_name_mds_gives_it() -> None:
    other_windows_hello = UUID("11111111-2222-3333-4444-555555555555")
    entry = {
        "description": "Windows Hello Future Authenticator",
        "icon": None,
        "key_protection": ["hardware"],
        "attachment_hint": [],
    }
    resolver = AuthenticatorInfoResolver(FakeStore({other_windows_hello: entry}))
    classification = resolver.classify(webauthn(aaguid=other_windows_hello))
    assert classification.kind is KeyKind.PASSKEY


def test_a_platform_attachment_is_no_evidence_of_a_discoverable_credential(resolver: AuthenticatorInfoResolver) -> None:
    def credential(created_ts: datetime) -> Webauthn:
        return webauthn(
            aaguid=PASSWORD_MANAGER,
            attestation_format=AttestationFormat.NONE,
            authenticator=AuthenticatorAttachment.PLATFORM,
            created_ts=created_ts,
        )

    assert resolver.classify(credential(BEFORE)).kind is KeyKind.PASSKEY
    # nothing known without a cutoff, and before it only that the registration did not ask for one
    assert resolver.classify(credential(BEFORE)).discoverable is Discoverable.UNKNOWN
    assert resolver.classify(credential(BEFORE), resident_key_cutoff=CUTOFF).discoverable is Discoverable.UNKNOWN
    assert resolver.classify(credential(AFTER)).discoverable is Discoverable.UNKNOWN
    assert resolver.classify(credential(AFTER), resident_key_cutoff=CUTOFF).discoverable is Discoverable.LIKELY


def test_nothing_derived_from_stored_data_alone_is_a_definite_yes(resolver: AuthenticatorInfoResolver) -> None:
    for attachment in AuthenticatorAttachment:
        for aaguid in (YUBIKEY, WINDOWS_HELLO, ANDROID, PASSWORD_MANAGER, ZERO_AAGUID):
            credential = webauthn(aaguid=aaguid, authenticator=attachment, attestation_format=AttestationFormat.APPLE)
            assert resolver.classify(credential, resident_key_cutoff=CUTOFF).discoverable is not Discoverable.YES
