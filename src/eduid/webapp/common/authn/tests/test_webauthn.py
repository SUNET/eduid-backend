"""Tests for shared WebAuthn registration (verify_webauthn_registration).

Regression coverage for keyhandle format: must be base64url (registration.id),
not hex of credential_id. Using hex breaks credential lookup by ElementKey since
Webauthn.key = sha256(keyhandle + credential_data).
"""

import base64
from unittest.mock import MagicMock

import pytest
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import AttestedCredentialData, AuthenticatorAttachment

from eduid.userdb.credentials import Webauthn
from eduid.webapp.common.authn.webauthn import (
    RegistrationError,
    RegistrationResult,
    verify_webauthn_registration,
)

# CTAP1 test data — same attestation fixtures as security/signup tests (Yubikey U2F)
STATE = {"challenge": "u3zHzb7krB4c4wj0Uxuhsz2lCXqLnwV9ZxMhvL2lcfo", "user_verification": "discouraged"}

ATTESTATION_OBJECT = (
    b"o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgPCNiKlxIO0iR5Wo9BidnNhX2lAFcAB3VwuRH"
    b"QZbL3dwCIQDFKuPjwLTvjaDw9TbfoJeww7DMsZSlteW4ClwRivpUqWN4NWOBWQIzMIICLzCCARmgAwIB"
    b"AgIEQvUaTTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0"
    b"NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1Ymlj"
    b"byBVMkYgRUUgU2VyaWFsIDExMjMzNTkzMDkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQphQ-PJYiZ"
    b"jZEVHtrx5QGE3_LE1-OytZPTwzrpWBKywji_3qmg22mwmVFl32PO269TxY-yVN4jbfVf5uX0EWJWoyYw"
    b"JDAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNDALBgkqhkiG9w0BAQsDggEBALSc3YwT"
    b"RbLwXhePj_imdBOhWiqh6ssS2ONgp5tphJCHR5Agjg2VstLBRsJzyJnLgy7bGZ0QbPOyh_J0hsvgBfvj"
    b"ByXOu1AwCW-tcoJ-pfxESojDLDn8hrFph6eWZoCtBsWMDh6vMqPENeP6grEAECWx4fTpBL9Bm7F-0Rp_"
    b"d1_l66g4IhF_ZvuRFhY-BUK94BfivuBHpEkMwxKENTas7VkxvlVstUvPqhPHGYOq7RdF1D_THsbNY8-t"
    b"gCTgvTziEG-bfDeY6zIz5h7bxb1rpajNVTpUDWtVYL7_w44e1KCoErqdS-kEbmmkmm7KvDE8kuyg42Fm"
    b"b5DTMsbY2jxMlMVoYXV0aERhdGFYxNz3BHEmKmoM4iTRAmMUgSjEdNSeKZskhyDzwzPuNmHTQQAAAAAA"
    b"AAAAAAAAAAAAAAAAAAAAAEC8lMNeMgJDZOvOHus-78SI8YvR3HVUwv2NR3PcfvBndpabw-UiQQjx4N-T"
    b"lJZcGJFfhzzQ9oAnkvZhcwGGTdtLpQECAyYgASFYIOHIO6vueJNYEgtQUy_wdwVka6DrKYSXnsIM6nfx"
    b"-mtgIlggkCpDejidmogF4SZ_n01JlE8dY43tFEIwAPy2qCGinzQ"
)

CLIENT_DATA_JSON = (
    b"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidTN6SHpiN2tyQjRjNHdqMFV4dWhz"
    b"ejJsQ1hxTG53VjlaeE1odkwybGNmbyIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmVkdWlkLmRv"
    b"Y2tlciIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
)

# Correct base64url credential ID (matches what's embedded in the attestation object above)
CREDENTIAL_ID_B64URL = "vJTDXjICQ2Trzh7rPu_EiPGL0dx1VML9jUdz3H7wZ3aWm8PlIkEI8eDfk5SWXBiRX4c80PaAJ5L2YXMBhk3bSw"

# Same credential ID as hex — the OLD broken format used before the shared registration refactor
CREDENTIAL_ID_HEX = (
    "bc94c35e32024364ebce1eeb3eefc488f18bd1dc7554c2fd8d4773dc7ef06776"
    "969bc3e5224108f1e0df9394965c18915f873cd0f6802792f6617301864ddb4b"
)


def _make_response(credential_id: str = CREDENTIAL_ID_B64URL) -> dict:
    return {
        "credentialId": credential_id,
        "rawId": credential_id,
        "response": {
            "attestationObject": ATTESTATION_OBJECT.decode("ascii").strip("="),
            "clientDataJSON": CLIENT_DATA_JSON.decode("ascii").strip("="),
        },
    }


def _register(**kwargs) -> RegistrationResult:
    defaults = dict(
        response=_make_response(),
        webauthn_state=STATE,
        authenticator=AuthenticatorAttachment.CROSS_PLATFORM,
        rp_id="eduid.docker",
        rp_name="eduID",
        fido_mds=MagicMock(),
        fido_metadata_log=MagicMock(),
        app_name="testing",
        is_backdoor=True,
    )
    defaults.update(kwargs)
    return verify_webauthn_registration(**defaults)


class TestVerifyWebauthnRegistration:
    def test_keyhandle_is_base64url_not_hex(self) -> None:
        """Regression: keyhandle must be base64url, not hex of credential_id."""
        result = _register()

        assert result.keyhandle == CREDENTIAL_ID_B64URL
        assert result.keyhandle != CREDENTIAL_ID_HEX

    def test_keyhandle_round_trips_to_credential_id_bytes(self) -> None:
        result = _register()

        decoded = websafe_decode(result.keyhandle)
        assert decoded == bytes.fromhex(CREDENTIAL_ID_HEX)
        assert websafe_encode(decoded) == result.keyhandle

    def test_credential_key_differs_from_hex_keyhandle(self) -> None:
        """Webauthn.key depends on keyhandle — hex vs base64url produces different keys."""
        result = _register()

        correct_credential = Webauthn(
            keyhandle=result.keyhandle,
            credential_data=result.credential_data,
            app_id="eduid.docker",
            created_by="testing",
            authenticator=result.authenticator,
        )
        broken_credential = Webauthn(
            keyhandle=CREDENTIAL_ID_HEX,
            credential_data=result.credential_data,
            app_id="eduid.docker",
            created_by="testing",
            authenticator=result.authenticator,
        )

        assert correct_credential.key != broken_credential.key

    def test_credential_data_unpacks_to_matching_credential_id(self) -> None:
        """Stored credential_data contains the same credential_id as the keyhandle."""
        result = _register()

        decoded = base64.urlsafe_b64decode(result.credential_data.encode("ascii"))
        cred_data, rest = AttestedCredentialData.unpack_from(decoded)
        assert not rest
        assert websafe_encode(cred_data.credential_id) == result.keyhandle

    def test_registration_result_fields(self) -> None:
        result = _register()

        assert isinstance(result, RegistrationResult)
        assert result.authenticator == AuthenticatorAttachment.CROSS_PLATFORM
        assert result.authenticator_info is not None
        assert result.authenticator_info.user_present is True
        assert result.mfa_approved is False
        assert result.is_discoverable is False

    def test_discoverable_credential_from_credprops(self) -> None:
        result = _register(
            authenticator=AuthenticatorAttachment.PLATFORM,
            client_extension_results={"credProps": {"rk": True}},
        )

        assert result.is_discoverable is True

    def test_non_discoverable_without_credprops(self) -> None:
        result = _register()
        assert result.is_discoverable is False

    def test_credprops_without_rk(self) -> None:
        result = _register(client_extension_results={"credProps": {}})
        assert result.is_discoverable is False

    def test_credprops_rk_false(self) -> None:
        result = _register(client_extension_results={"credProps": {"rk": False}})
        assert result.is_discoverable is False

    def test_invalid_attestation_raises(self) -> None:
        bad_response = _make_response()
        bad_response["response"]["attestationObject"] = "aW52YWxpZA"

        with pytest.raises((RegistrationError, ValueError)):
            _register(response=bad_response)

    def test_wrong_challenge_raises_registration_error(self) -> None:
        wrong_state = {
            "challenge": "WRONG_CHALLENGE_aaaaaaaaaaaaaaaaaaaaaaaaa",
            "user_verification": "discouraged",
        }

        with pytest.raises(RegistrationError, match="registration completion failed"):
            _register(webauthn_state=wrong_state)

    def test_wrong_rp_id_raises_registration_error(self) -> None:
        with pytest.raises(RegistrationError, match="registration completion failed"):
            _register(rp_id="wrong.rp.id")

    def test_credential_lookup_matches_raw_id(self) -> None:
        """Credential stored via registration can be found by raw credential_id bytes (as fido_tokens.py does)."""
        result = _register()

        credential = Webauthn(
            keyhandle=result.keyhandle,
            credential_data=result.credential_data,
            app_id="eduid.docker",
            created_by="testing",
            authenticator=result.authenticator,
        )

        cred_data_bytes = base64.urlsafe_b64decode(credential.credential_data.encode("ascii"))
        unpacked, _ = AttestedCredentialData.unpack_from(cred_data_bytes)

        raw_id = websafe_decode(result.keyhandle)
        assert unpacked.credential_id == raw_id
