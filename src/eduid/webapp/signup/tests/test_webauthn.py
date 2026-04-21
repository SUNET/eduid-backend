import base64
import json
import logging
from collections.abc import Mapping
from typing import Any

import pytest
from fido2.webauthn import AuthenticatorAttachment, RegistrationResponse
from jwcrypto.jwk import JWK
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.config.base import EduidEnvironment
from eduid.userdb.credentials import Password, Webauthn
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.webauthn import get_webauthn_server
from eduid.webapp.common.session.eduid_session import EduidSession
from eduid.webapp.common.session.namespaces import WebauthnCredential, WebauthnRegistration, WebauthnState
from eduid.webapp.signup.app import SignupApp, signup_init_app
from eduid.webapp.signup.helpers import SignupMsg

logger = logging.getLogger(__name__)

# CTAP1 test data (copied from security tests)

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

CREDENTIAL_ID = (
    "31f8974379e65869f9b7caaf28f0e44eead0fdd883e9c545404e351824a6c4cea738613e4ef5b9"
    "d699fbc4d6bab05117a13cc81875b732e00058027155ced047"
)


class SignupWebauthnTests(EduidAPITestCase[SignupApp]):
    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None, mocker: MockerFixture) -> None:
        self.mocker = mocker

    def load_app(self, config: Mapping[str, Any]) -> SignupApp:
        return signup_init_app(name="signup", test_config=config)

    @pytest.fixture(scope="class")
    def update_config(self) -> dict[str, Any]:
        config = self._get_base_config()
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "signup_url": "https://localhost/",
                "dashboard_url": "https://localhost/",
                "development": "DEBUG",
                "application_root": "/",
                "log_level": "DEBUG",
                "password_length": 10,
                "vccs_url": "http://turq:13085/",
                "default_finish_url": "https://www.eduid.se/",
                "captcha_max_bad_attempts": 3,
                "environment": "dev",
                "fido2_rp_id": "eduid.docker",
                "scim_api_url": "http://localhost/scim/",
                "gnap_auth_data": {
                    "authn_server_url": "http://localhost/auth/",
                    "key_name": "app_name",
                    "client_jwk": JWK.generate(kid="testkey", kty="EC", size=256).export(as_dict=True),
                },
            }
        )
        return config

    def _prepare_for_webauthn(self) -> None:
        """Set session state as if captcha, email verify, and ToU are completed."""
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                sess.signup.captcha.completed = True
                sess.signup.email.address = "test@example.com"
                sess.signup.email.completed = True
                sess.signup.email.reference = "test_ref"
                sess.signup.tou.completed = True
                sess.signup.tou.version = "test_tou_v1"
                sess.signup.name.given_name = "Test"
                sess.signup.name.surname = "Testdotter"

    def _begin_register_webauthn(
        self,
        authenticator: str = "cross-platform",
    ) -> TestResponse:
        """Call POST /webauthn/register/begin with magic cookie."""
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        with self.session_cookie(self.browser, eppn=None) as client:
            client.set_cookie(domain=self.test_domain, key="magic", value="magic-cookie")
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
                data = {"csrf_token": csrf_token, "authenticator": authenticator}
            response = client.post(
                "/webauthn/register/begin", data=json.dumps(data), content_type=self.content_type_json
            )
            return response

    def _complete_register_webauthn(self) -> TestResponse:
        """Set WebauthnRegistration in session, call POST /webauthn/register/complete with magic cookie."""
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        webauthn_state = WebauthnState(STATE)
        with self.session_cookie(self.browser, eppn=None) as client:
            client.set_cookie(domain=self.test_domain, key="magic", value="magic-cookie")
            with client.session_transaction() as sess:
                assert isinstance(sess, EduidSession)
                sess.signup.credentials.webauthn_registration = WebauthnRegistration(
                    webauthn_state=webauthn_state, authenticator=AuthenticatorAttachment.CROSS_PLATFORM
                )
                csrf_token = sess.get_csrf_token()
                data = {
                    "csrf_token": csrf_token,
                    "response": {
                        "credentialId": CREDENTIAL_ID,
                        "rawId": CREDENTIAL_ID,
                        "response": {
                            "attestationObject": ATTESTATION_OBJECT.decode(),
                            "clientDataJSON": CLIENT_DATA_JSON.decode(),
                            "credentialId": CREDENTIAL_ID,
                        },
                    },
                    "description": "test security key",
                }
            response = client.post(
                "/webauthn/register/complete", data=json.dumps(data), content_type=self.content_type_json
            )
            return response

    def _create_user_with_webauthn(
        self,
        use_suggested_password: bool = False,
        use_webauthn: bool = True,
        generated_password: str | None = None,
        custom_password: str | None = None,
    ) -> TestResponse:
        """Call POST /create-user with webauthn flag."""
        mock_request_user_sync = self.mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_add_credentials = self.mocker.patch("eduid.vccs.client.VCCSClient.add_credentials")
        mock_add_credentials.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
                data: dict[str, Any] = {
                    "csrf_token": csrf_token,
                    "use_suggested_password": use_suggested_password,
                    "use_webauthn": use_webauthn,
                }
                if custom_password is not None:
                    data["custom_password"] = custom_password
            response = client.post("/create-user", json=data)
            return response

    def _set_webauthn_credential_in_session(self, is_discoverable: bool = True) -> None:
        """Register a webauthn credential using the test fixtures and store the result in the session."""
        server = get_webauthn_server(rp_id=self.app.conf.fido2_rp_id, rp_name=self.app.conf.fido2_rp_name)
        reg_response = {
            "credentialId": CREDENTIAL_ID,
            "rawId": CREDENTIAL_ID,
            "response": {
                "attestationObject": ATTESTATION_OBJECT.decode("ascii").strip("="),
                "clientDataJSON": CLIENT_DATA_JSON.decode("ascii").strip("="),
            },
        }
        registration = RegistrationResponse.from_dict(reg_response)
        auth_data = server.register_complete(state=STATE, response=registration)
        assert auth_data.credential_data is not None

        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                sess.signup.credentials.webauthn = WebauthnCredential(
                    credential_data=base64.urlsafe_b64encode(auth_data.credential_data).decode("ascii"),
                    keyhandle=auth_data.credential_data.credential_id.hex(),
                    authenticator=AuthenticatorAttachment.CROSS_PLATFORM,
                    authenticator_id="test-authenticator-id",
                    description="test security key",
                    is_discoverable=is_discoverable,
                )
                sess.signup.credentials.completed = True

    # --- Tests ---

    def test_webauthn_register_begin(self) -> None:
        """Happy path: verify response type and registration_data."""
        self._prepare_for_webauthn()
        response = self._begin_register_webauthn()
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_WEBAUTHN_REGISTER_BEGIN_SUCCESS"
        assert "registration_data" in data["payload"]
        assert "csrf_token" in data["payload"]

    def test_webauthn_register_begin_generates_eppn(self) -> None:
        """Verify that session.signup.eppn is set after begin."""
        self._prepare_for_webauthn()
        self._begin_register_webauthn()
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                assert sess.signup.eppn is not None

    def test_webauthn_register_begin_requires_captcha(self) -> None:
        """Unset captcha, expect failure."""
        self._prepare_for_webauthn()
        # Unset captcha completed
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                sess.signup.captcha.completed = False
        response = self._begin_register_webauthn()
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_WEBAUTHN_REGISTER_BEGIN_FAIL"
        assert data["payload"]["message"] == SignupMsg.captcha_not_completed.value

    def test_webauthn_register_begin_requires_email_verified(self) -> None:
        """Unset email, expect failure."""
        self._prepare_for_webauthn()
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                sess.signup.email.completed = False
        response = self._begin_register_webauthn()
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_WEBAUTHN_REGISTER_BEGIN_FAIL"
        assert data["payload"]["message"] == SignupMsg.email_verification_not_complete.value

    def test_webauthn_register_begin_requires_tou(self) -> None:
        """Unset tou, expect failure."""
        self._prepare_for_webauthn()
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                sess.signup.tou.completed = False
        response = self._begin_register_webauthn()
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_WEBAUTHN_REGISTER_BEGIN_FAIL"
        assert data["payload"]["message"] == SignupMsg.tou_not_completed.value

    def test_webauthn_register_complete(self) -> None:
        """Happy path with mocked state, verify credentials.completed and webauthn_registered."""
        self._prepare_for_webauthn()
        response = self._complete_register_webauthn()
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_WEBAUTHN_REGISTER_COMPLETE_SUCCESS"
        assert data["payload"]["state"]["credentials"]["completed"] is True
        assert data["payload"]["state"]["credentials"]["webauthn_registered"] is True

    def test_webauthn_register_complete_no_state(self) -> None:
        """No registration in session, expect failure."""
        self._prepare_for_webauthn()
        # Do NOT set webauthn_registration in session; just call complete directly
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        with self.session_cookie(self.browser, eppn=None) as client:
            client.set_cookie(domain=self.test_domain, key="magic", value="magic-cookie")
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
                data = {
                    "csrf_token": csrf_token,
                    "response": {
                        "credentialId": CREDENTIAL_ID,
                        "rawId": CREDENTIAL_ID,
                        "response": {
                            "attestationObject": ATTESTATION_OBJECT.decode(),
                            "clientDataJSON": CLIENT_DATA_JSON.decode(),
                            "credentialId": CREDENTIAL_ID,
                        },
                    },
                    "description": "test security key",
                }
            response = client.post(
                "/webauthn/register/complete", data=json.dumps(data), content_type=self.content_type_json
            )
        resp_data = response.json
        assert resp_data is not None
        assert resp_data["type"] == "POST_SIGNUP_WEBAUTHN_REGISTER_COMPLETE_FAIL"
        assert resp_data["payload"]["message"] == SignupMsg.webauthn_registration_failed.value

    def test_create_user_with_webauthn_only(self) -> None:
        """Full flow with webauthn passkey (discoverable), no password."""
        self._prepare_for_webauthn()
        self._set_webauthn_credential_in_session(is_discoverable=True)
        response = self._create_user_with_webauthn(use_suggested_password=False, use_webauthn=True)
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_CREATE_USER_SUCCESS"
        assert data["payload"]["state"]["user_created"] is True
        assert data["payload"]["state"]["credentials"]["completed"] is True
        assert data["payload"]["state"]["credentials"]["webauthn_registered"] is True
        assert data["payload"]["state"]["credentials"]["webauthn_is_discoverable"] is True

        # Verify the user was created with a webauthn credential
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
                assert eppn is not None
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        webauthn_creds = user.credentials.filter(Webauthn)
        assert len(webauthn_creds) == 1
        passwords = user.credentials.filter(Password)
        assert len(passwords) == 0

    def test_create_user_with_non_discoverable_webauthn_without_password(self) -> None:
        """Non-discoverable security key + no password -> error, no user created."""
        self._prepare_for_webauthn()
        self._set_webauthn_credential_in_session(is_discoverable=False)
        response = self._create_user_with_webauthn(use_suggested_password=False, use_webauthn=True)
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_CREATE_USER_FAIL"
        assert data["payload"]["message"] == SignupMsg.password_required.value

        # No user should have been created
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                assert sess.common.eppn is None
                assert sess.signup.user_created is False

    def test_create_user_with_non_discoverable_webauthn_and_password(self) -> None:
        """Non-discoverable security key + generated password -> user created with both credentials."""
        self._prepare_for_webauthn()
        self._set_webauthn_credential_in_session(is_discoverable=False)
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                sess.signup.credentials.generated_password = "test_password"

        response = self._create_user_with_webauthn(use_suggested_password=True, use_webauthn=True)
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_CREATE_USER_SUCCESS"
        assert data["payload"]["state"]["user_created"] is True
        assert data["payload"]["state"]["credentials"]["webauthn_registered"] is True
        assert data["payload"]["state"]["credentials"]["webauthn_is_discoverable"] is False

        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
                assert eppn is not None
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        webauthn_creds = user.credentials.filter(Webauthn)
        assert len(webauthn_creds) == 1
        passwords = user.credentials.filter(Password)
        assert len(passwords) == 1

    def test_create_user_with_credprops_absent_requires_password(self) -> None:
        """When credProps is absent from the registration response, credential is treated as non-discoverable."""
        self._prepare_for_webauthn()
        # Go through the real register/complete path (no client_extension_results in payload)
        response = self._complete_register_webauthn()
        assert response.json is not None
        assert response.json["type"] == "POST_SIGNUP_WEBAUTHN_REGISTER_COMPLETE_SUCCESS"
        assert response.json["payload"]["state"]["credentials"]["webauthn_is_discoverable"] is False

        # No password set -> must be rejected
        create_response = self._create_user_with_webauthn(use_suggested_password=False, use_webauthn=True)
        create_data = create_response.json
        assert create_data is not None
        assert create_data["type"] == "POST_SIGNUP_CREATE_USER_FAIL"
        assert create_data["payload"]["message"] == SignupMsg.password_required.value

    def test_webauthn_register_complete_with_credprops_rk_true(self) -> None:
        """credProps.rk=True in clientExtensionResults -> is_discoverable True in session + response."""
        self._prepare_for_webauthn()
        self.app.conf.magic_cookie = "magic-cookie"
        self.app.conf.magic_cookie_name = "magic"
        self.app.conf.environment = EduidEnvironment("dev")

        webauthn_state = WebauthnState(STATE)
        with self.session_cookie(self.browser, eppn=None) as client:
            client.set_cookie(domain=self.test_domain, key="magic", value="magic-cookie")
            with client.session_transaction() as sess:
                assert isinstance(sess, EduidSession)
                sess.signup.credentials.webauthn_registration = WebauthnRegistration(
                    webauthn_state=webauthn_state, authenticator=AuthenticatorAttachment.CROSS_PLATFORM
                )
                csrf_token = sess.get_csrf_token()
                data = {
                    "csrf_token": csrf_token,
                    "response": {
                        "credentialId": CREDENTIAL_ID,
                        "rawId": CREDENTIAL_ID,
                        "response": {
                            "attestationObject": ATTESTATION_OBJECT.decode(),
                            "clientDataJSON": CLIENT_DATA_JSON.decode(),
                            "credentialId": CREDENTIAL_ID,
                        },
                    },
                    "description": "test passkey",
                    "clientExtensionResults": {"credProps": {"rk": True}},
                }
            response = client.post(
                "/webauthn/register/complete", data=json.dumps(data), content_type=self.content_type_json
            )
        resp_data = response.json
        assert resp_data is not None
        assert resp_data["type"] == "POST_SIGNUP_WEBAUTHN_REGISTER_COMPLETE_SUCCESS"
        assert resp_data["payload"]["state"]["credentials"]["webauthn_is_discoverable"] is True

        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                assert sess.signup.credentials.webauthn is not None
                assert sess.signup.credentials.webauthn.is_discoverable is True

    def test_create_user_with_password_and_webauthn(self) -> None:
        """Full flow with both password and webauthn."""
        self._prepare_for_webauthn()
        self._set_webauthn_credential_in_session()
        # Also set a generated password
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                sess.signup.credentials.generated_password = "test_password"

        response = self._create_user_with_webauthn(use_suggested_password=True, use_webauthn=True)
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_CREATE_USER_SUCCESS"
        assert data["payload"]["state"]["user_created"] is True
        assert data["payload"]["state"]["credentials"]["completed"] is True
        assert data["payload"]["state"]["credentials"]["webauthn_registered"] is True

        # Verify the user was created with both credentials
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
                assert eppn is not None
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        assert user is not None
        webauthn_creds = user.credentials.filter(Webauthn)
        assert len(webauthn_creds) == 1
        passwords = user.credentials.filter(Password)
        assert len(passwords) == 1
        assert passwords[0].is_generated is True

    def test_create_user_no_credential(self) -> None:
        """Neither password nor webauthn, expect failure."""
        self._prepare_for_webauthn()
        response = self._create_user_with_webauthn(use_suggested_password=False, use_webauthn=False)
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_CREATE_USER_FAIL"
        assert data["payload"]["message"] == SignupMsg.credential_not_added.value

    def test_create_user_with_mfa_approved_webauthn(self) -> None:
        """Verify proofing log is written when webauthn credential is MFA-approved."""
        self._prepare_for_webauthn()

        # Set up credential with mfa_approved=True and user_verified=True
        server = get_webauthn_server(rp_id=self.app.conf.fido2_rp_id, rp_name=self.app.conf.fido2_rp_name)
        reg_response = {
            "credentialId": CREDENTIAL_ID,
            "rawId": CREDENTIAL_ID,
            "response": {
                "attestationObject": ATTESTATION_OBJECT.decode("ascii").strip("="),
                "clientDataJSON": CLIENT_DATA_JSON.decode("ascii").strip("="),
            },
        }
        registration = RegistrationResponse.from_dict(reg_response)
        auth_data = server.register_complete(state=STATE, response=registration)
        assert auth_data.credential_data is not None

        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                sess.signup.credentials.webauthn = WebauthnCredential(
                    credential_data=base64.urlsafe_b64encode(auth_data.credential_data).decode("ascii"),
                    keyhandle=auth_data.credential_data.credential_id.hex(),
                    authenticator=AuthenticatorAttachment.CROSS_PLATFORM,
                    authenticator_id="test-authenticator-id",
                    mfa_approved=True,
                    user_verified=True,
                    description="mfa security key",
                    is_discoverable=True,
                )
                sess.signup.credentials.completed = True

        response = self._create_user_with_webauthn(use_suggested_password=False, use_webauthn=True)
        data = response.json
        assert data is not None
        assert data["type"] == "POST_SIGNUP_CREATE_USER_SUCCESS"

        # Verify proofing log was written
        with self.session_cookie(self.browser, eppn=None) as client:
            with client.session_transaction() as sess:
                eppn = sess.common.eppn
                assert eppn is not None
        proofing_logs = self.app.proofing_log._coll.find({"eduPersonPrincipalName": eppn})
        # Should have mail address proofing + webauthn mfa capability proofing
        log_entries = list(proofing_logs)
        proofing_types = [entry.get("proofing_method") for entry in log_entries]
        assert "webauthn metadata" in proofing_types
