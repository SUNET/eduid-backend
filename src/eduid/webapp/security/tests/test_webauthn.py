import base64
import json
from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock, patch

from fido2.utils import websafe_decode
from fido2.webauthn import (
    AuthenticatorAttachment,
    RegistrationResponse,
    UserVerificationRequirement,
)
from fido_mds import FidoMetadataStore
from future.backports.datetime import timedelta
from werkzeug.http import dump_cookie
from werkzeug.test import TestResponse

from eduid.common.config.base import EduidEnvironment, FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import U2F, FidoCredential, Webauthn
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.schemas.authn_status import AuthnActionStatus
from eduid.webapp.common.api.testing import CSRFTestClient, EduidAPITestCase
from eduid.webapp.common.session import EduidSession
from eduid.webapp.common.session.namespaces import WebauthnRegistration, WebauthnState
from eduid.webapp.security.app import SecurityApp, security_init_app
from eduid.webapp.security.views.webauthn import get_webauthn_server
from eduid.webapp.security.webauthn_proofing import get_authenticator_information, is_authenticator_mfa_approved

__author__ = "eperez"


# CTAP1 test data

# result of calling Fido2Server.register_begin
from fido_mds import Attestation
from fido_mds.models.webauthn import AttestationFormat
from fido_mds.tests.data import IPHONE_12, MICROSOFT_SURFACE_1796, NEXUS_5, NONE_ATTESTATION, YUBIKEY_4, YUBIKEY_5_NFC

# CTAP1 security key
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

# CTAP2 security key
STATE_2 = {"challenge": "yxHWG+ouoa8MLGSxOJJhM0NtiH5ubK3BPfx+6uE3QkU=", "user_verification": "required"}

ATTESTATION_OBJECT_2 = b"""
o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgHFOTISd2NExUtGr1GTkgImVIJx09yJfKdx7j1f714r0CIF6vTppPv1mRyism5kZjMq+pEvi3
BATxv2m/kRvlD5zhY3g1Y4FZAsEwggK9MIIBpaADAgECAgQej4c0MA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJp
YWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBuMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQL
DBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMScwJQYDVQQDDB5ZdWJpY28gVTJGIEVFIFNlcmlhbCA1MTI3MjI3NDAwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAASoefgjOO0UlLrAcEvMf8Zj0bJxcVl2JDEBx2BRFdfBUp4oHBxnMi04S1zVXdPpgY1f2FwirzJuDGT8IK/jPyNmo2wwajAiBgkrBgEEAYLECgIEFTEu
My42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBAvwFefgRNH6rEWu1qNuSAqMAwGA1UdEwEB/wQCMAAw
DQYJKoZIhvcNAQELBQADggEBAIaT/2LfDVd51HSNf8jRAicxio5YDmo6V8EI6U4Dw4Vos2aJT85WJL5KPv1/NBGLPZk3Q/eSoZiRYMj8muCwTj357hXj6IwE
/IKo3L9YGOEI3MKWhXeuef9mK5RzTj3sRZcwXXPm5V7ivrnNlnjKCTXlM+tjj44m+ruBfNpEH76YMYMq5fbirZkvnrvbTGIji4+NerSB1tMmO82/nkpXVQNw
mIrVgTRA+gMsrbZyPK3Y+Ne6gJ91tDz/oKW5rdFCMu+dnhSBJjgjPEykqHO5+KyY4yuhkWdgbhWQn83bSi3/va5GICSfmmZGrIHkgy0RGf6/qnMaiC2iWneC
fUbRkBdoYXV0aERhdGFYxNz3BHEmKmoM4iTRAmMUgSjEdNSeKZskhyDzwzPuNmHTRQAAAAIvwFefgRNH6rEWu1qNuSAqAEDl1oXc7ZWmdlYmRhcoe5htjx6D
+mBRxGkyn3o/xCQfq0FrCveEmEHkG9YmfOxgM77SQrRfG9o3jHuZfpEBLZwopQECAyYgASFYIAFrblN2QOoc1mGVVyS5SvjcQsg2aDZrqfHnrb0iTTiJIlgg
PJvxSmTxEspL+STelnGuWKgEIiAGR9S+snHAGqkaYf4=
"""

CLIENT_DATA_JSON_2 = b"""
eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoieXhIV0ctb3VvYThNTEdTeE9KSmhNME50aUg1dWJLM0JQZngtNnVFM1FrVSIsIm9yaWdp
biI6Imh0dHBzOi8vaHRtbC5lZHVpZC5kb2NrZXIiLCJjcm9zc09yaWdpbiI6ZmFsc2V9
"""

CREDENTIAL_ID_2 = (
    "7bad3b59fa16e9e8840e2fd15c026a3c9a7d2877fd7d97c25a3b3158d1a9cba1e14b7c9913915"
    "f912366c18bd06bc9e903bc779409a8a7c749511e2b44e54c88"
)


class SecurityWebauthnTests(EduidAPITestCase):
    app: SecurityApp

    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)
        # remove all FidoCredentials from the test user
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user is not None
        for credential in user.credentials:
            if isinstance(credential, FidoCredential):
                user.credentials.remove(credential.key)
        self.app.central_userdb.save(user)

    def load_app(self, config: Mapping[str, Any]) -> SecurityApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "webauthn_max_allowed_tokens": 10,
                "fido2_rp_id": "eduid.docker",
                "vccs_url": "https://vccs",
                "dashboard_url": "https://dashboard",
            }
        )
        return config

    def _add_token_to_user(self, client_data: bytes, attestation: bytes, state: Mapping[str, Any]) -> Webauthn:
        response = {
            "credentialId": CREDENTIAL_ID,
            "rawId": CREDENTIAL_ID,
            "response": {
                "attestationObject": attestation.decode("ascii").strip("="),
                "clientDataJSON": client_data.decode("ascii").strip("="),
            },
        }
        registration = RegistrationResponse.from_dict(response)

        server = get_webauthn_server(rp_id=self.app.conf.fido2_rp_id, rp_name=self.app.conf.fido2_rp_name)
        auth_data = server.register_complete(state=state, response=registration)
        cred_data = auth_data.credential_data
        assert cred_data is not None  # please mypy
        cred_id = cred_data.credential_id

        credential = Webauthn(
            keyhandle=cred_id.hex(),
            credential_data=base64.urlsafe_b64encode(cred_data).decode("ascii"),
            app_id=self.app.conf.fido2_rp_id,
            description="ctap1 token",
            created_by="test_security",
            authenticator=AuthenticatorAttachment.CROSS_PLATFORM,
        )
        test_user = self.app.central_userdb.get_user_by_eppn(self.test_user.eppn)
        test_user.credentials.add(credential)
        self.app.central_userdb.save(test_user)
        return credential

    def _add_u2f_token_to_user(self, eppn: str) -> U2F:
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        u2f_token = U2F(
            version="version",
            keyhandle="keyHandle",
            app_id="appId",
            public_key="publicKey",
            attest_cert="cert",
            description="description",
            created_by="eduid_security",
        )
        user.credentials.add(u2f_token)
        self.app.central_userdb.save(user)
        return u2f_token

    @staticmethod
    def _response_json_to_dict(response: TestResponse) -> dict[Any, Any]:
        data = response.json
        assert data is not None, "No json data returned"
        assert isinstance(data, dict) is True, "returned json is not a dict"
        return data

    def _check_session_state(self, client: CSRFTestClient) -> None:
        with client.session_transaction() as sess:
            assert isinstance(sess, EduidSession)
            assert sess.security.webauthn_registration is not None
            webauthn_state = sess.security.webauthn_registration.webauthn_state
        assert webauthn_state["user_verification"] == UserVerificationRequirement.PREFERRED.value
        assert "challenge" in webauthn_state

    def _check_registration_begun(self, data: dict) -> None:
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_SUCCESS")
        self.assertIn("registration_data", data["payload"])
        self.assertIn("csrf_token", data["payload"])

    def _check_registration_complete(self, data: dict) -> None:
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REGISTER_COMPLETE_SUCCESS")
        self.assertTrue(len(data["payload"]["credentials"]) > 0)
        self.assertEqual(data["payload"]["message"], "security.webauthn_register_success")

    def _check_removal(self, data: dict, user_token: Webauthn) -> None:
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REMOVE_SUCCESS")
        self.assertIsNotNone(data["payload"]["credentials"])
        for credential in data["payload"]["credentials"]:
            self.assertIsNotNone(credential)
            self.assertNotEqual(credential["key"], user_token.key)

    # parameterized test methods
    def _begin_register_key(
        self,
        other: str | None = None,
        authenticator: str = "cross-platform",
        existing_legacy_token: bool = False,
        csrf: str | None = None,
        check_session: bool = True,
        setup_authn_action: bool = True,
    ) -> TestResponse:
        """
        Start process to register a webauthn token for the test user,
        possibly adding U2F or webauthn credentials before.

        :param other: to control the credential (ctap1 or ctap2) added to the account.
        :param authenticator: which authenticator to use (platform|cross-platform)
        :param existing_legacy_token: whether to add a legacy U2F credential to the test user.
        :param csrf: to control the CSRF token to send
        :param check_session: whether to check the registration state in the session
        """

        force_mfa = False
        if other is not None or existing_legacy_token:
            # Fake that user used the other security key to authenticate
            force_mfa = True

        if setup_authn_action:
            self.set_authn_action(
                eppn=self.test_user_eppn,
                frontend_action=FrontendAction.ADD_SECURITY_KEY_AUTHN,
                mock_mfa=force_mfa,
            )

        if existing_legacy_token:
            self._add_u2f_token_to_user(self.test_user_eppn)

        if other == "ctap1":
            self._add_token_to_user(client_data=CLIENT_DATA_JSON, attestation=ATTESTATION_OBJECT, state=STATE)
        elif other == "ctap2":
            self._add_token_to_user(client_data=CLIENT_DATA_JSON_2, attestation=ATTESTATION_OBJECT_2, state=STATE_2)

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    if csrf is not None:
                        csrf_token = csrf
                    else:
                        csrf_token = sess.get_csrf_token()
                    data = {"csrf_token": csrf_token, "authenticator": authenticator}
            response2 = client.post(
                "/webauthn/register/begin", data=json.dumps(data), content_type=self.content_type_json
            )
            if check_session:
                self._check_session_state(client)

            return response2

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _finish_register_key(
        self,
        mock_request_user_sync: MagicMock,
        client_data: bytes,
        attestation: bytes,
        state: dict,
        cred_id: bytes,
        existing_legacy_token: bool = False,
        csrf: str | None = None,
        set_authn_action: bool = True,
    ) -> TestResponse:
        """
        Finish registering a webauthn token.

        :param client_data: client data passed to the authenticator by the client
        :param attestation: attestation object, to attest to the provenance of the authenticator and the data it emits
        :param state: mock the webauthn registration state kept in the session
        :param cred_id: credential ID
        :param existing_legacy_token: whether to add a legacy U2F credential to the test user.
        :param csrf: to control the CSRF token to send
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        force_mfa = False
        if existing_legacy_token:
            # Fake that user used the other security key to authenticate
            force_mfa = True

        if set_authn_action:
            self.set_authn_action(
                eppn=self.test_user_eppn,
                frontend_action=FrontendAction.ADD_SECURITY_KEY_AUTHN,
                mock_mfa=force_mfa,
            )

        if existing_legacy_token:
            self._add_u2f_token_to_user(self.test_user_eppn)

        webauthn_state = WebauthnState(state)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    assert isinstance(sess, EduidSession)
                    sess.security.webauthn_registration = WebauthnRegistration(
                        webauthn_state=webauthn_state, authenticator=AuthenticatorAttachment.CROSS_PLATFORM
                    )
                    if csrf is not None:
                        csrf_token = csrf
                    else:
                        csrf_token = sess.get_csrf_token()
                    data = {
                        "csrf_token": csrf_token,
                        "response": {
                            "credentialId": CREDENTIAL_ID,
                            "rawId": CREDENTIAL_ID,
                            "response": {
                                "attestationObject": attestation.decode(),
                                "clientDataJSON": client_data.decode(),
                                "credentialId": cred_id,
                            },
                        },
                        "description": "dummy description",
                    }
            response2 = client.post(
                "/webauthn/register/complete", data=json.dumps(data), content_type=self.content_type_json
            )
            return response2

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _remove(
        self,
        mock_request_user_sync: MagicMock,
        client_data: bytes,
        attestation: bytes,
        state: dict,
        client_data_2: bytes,
        attestation_2: bytes,
        state_2: dict,
        existing_legacy_token: bool = False,
        csrf: str | None = None,
    ) -> tuple[Webauthn, TestResponse]:
        """
        Send a POST request to remove a webauthn credential from the test user.
        Before sending the request, add 2 webauthn credentials (and possibly a legacy u2f credential) to the test user.

        :param client_data: client data as would be produced by a browser
        :param attestation: attestation object as would be produced by a browser
        :param state: registration state kept in the session
        :param client_data_2: client data as would be produced by a browser (for the 2nd webauthn credential)
        :param attestation_2: attestation object as would be produced by a browser (for the 2nd webauthn credential)
        :param state_2: registration state kept in the session (for the 2nd webauthn credential)
        :param existing_legacy_token: whether to add a legacy U2F credential to the test user.
        :param csrf: to control the CSRF token to send
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        if existing_legacy_token:
            self._add_u2f_token_to_user(self.test_user_eppn)

        user_token = self._add_token_to_user(client_data=client_data, attestation=attestation, state=state)
        self._add_token_to_user(client_data=client_data_2, attestation=attestation_2, state=state_2)

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with client.session_transaction() as sess:
                if csrf is not None:
                    csrf_token = csrf
                else:
                    csrf_token = sess.get_csrf_token()
            data = {
                "csrf_token": csrf_token,
                "credential_key": user_token.key,
            }
            response2 = client.post("/webauthn/remove", json=data)
            return user_token, response2

    def _apple_special_verify_attestation(
        self: FidoMetadataStore, attestation: Attestation, client_data: bytes
    ) -> bool:
        if attestation.fmt is AttestationFormat.PACKED:
            return self.verify_packed_attestation(attestation=attestation, client_data=client_data)
        if attestation.fmt is AttestationFormat.APPLE:
            # apple attestation cert in fido_mds test data is only valid for three days
            return True
        if attestation.fmt is AttestationFormat.TPM:
            return self.verify_tpm_attestation(attestation=attestation, client_data=client_data)
        if attestation.fmt is AttestationFormat.ANDROID_SAFETYNET:
            # android attestation cert in fido_mds test data is only valid for three months
            return True
        if attestation.fmt is AttestationFormat.FIDO_U2F:
            return self.verify_fido_u2f_attestation(attestation=attestation, client_data=client_data)
        raise NotImplementedError(f"verification of {attestation.fmt.value} not implemented")

    # actual tests

    def test_begin_no_login(self) -> None:
        response = self.browser.get("/webauthn/register/begin")
        self.assertEqual(response.status_code, 401)

    def test_begin_register_first_key(self) -> None:
        response = self._begin_register_key()
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_first_key_with_legacy_token(self) -> None:
        response = self._begin_register_key(existing_legacy_token=True)
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_2nd_key_ater_ctap1(self) -> None:
        response = self._begin_register_key(other="ctap1")
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_2nd_key_ater_ctap1_with_legacy_token(self) -> None:
        response = self._begin_register_key(other="ctap1", existing_legacy_token=True)
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_2nd_key_ater_ctap2(self) -> None:
        response = self._begin_register_key(other="ctap2")
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_2nd_key_ater_ctap2_with_legacy_token(self) -> None:
        response = self._begin_register_key(other="ctap2", existing_legacy_token=True)
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_first_device(self) -> None:
        response = self._begin_register_key(authenticator="platform")
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_first_device_with_legacy_token(self) -> None:
        response = self._begin_register_key(authenticator="platform", existing_legacy_token=True)
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_2nd_device_ater_ctap1(self) -> None:
        response = self._begin_register_key(other="ctap1", authenticator="platform")
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_2nd_device_ater_ctap1_with_legacy_token(self) -> None:
        response = self._begin_register_key(other="ctap1", authenticator="platform", existing_legacy_token=True)
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_2nd_device_ater_ctap2(self) -> None:
        response = self._begin_register_key(other="ctap2", authenticator="platform")
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_2nd_device_ater_ctap2_with_legacy_token(self) -> None:
        response = self._begin_register_key(other="ctap2", authenticator="platform", existing_legacy_token=True)
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_first_key_signup_authn(self) -> None:
        self.setup_signup_authn()
        response = self._begin_register_key(setup_authn_action=False)
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_first_key_signup_authn_to_old(self) -> None:
        self.setup_signup_authn(user_created_at=utc_now() - timedelta(minutes=10))
        response = self._begin_register_key(check_session=False, setup_authn_action=False)
        self._check_must_authenticate_response(
            response=response,
            type_="POST_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_FAIL",
            frontend_action=FrontendAction.ADD_SECURITY_KEY_AUTHN,
            authn_status=AuthnActionStatus.NOT_FOUND,
        )

    def test_begin_register_2nd_key_ater_ctap2_signup_authn(self) -> None:
        self.setup_signup_authn()
        response = self._begin_register_key(other="ctap2", setup_authn_action=False)
        self._check_registration_begun(self._response_json_to_dict(response))

    def test_begin_register_wrong_csrf_token(self) -> None:
        response = self._begin_register_key(csrf="wrong-token", check_session=False)
        data = self._response_json_to_dict(response)
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_FAIL")
        self.assertEqual(data["payload"]["error"]["csrf_token"], ["CSRF failed to validate"])

    def test_finish_register_ctap1(self) -> None:
        response = self._finish_register_key(
            client_data=CLIENT_DATA_JSON, attestation=ATTESTATION_OBJECT, state=STATE, cred_id=CREDENTIAL_ID
        )
        self._check_registration_complete(self._response_json_to_dict(response))
        # check that a proofing element was not written as the token is not mfa capable
        assert self.app.proofing_log.db_count() == 0

    def test_finish_register_ctap1_with_legacy_token(self) -> None:
        response = self._finish_register_key(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            cred_id=CREDENTIAL_ID,
            existing_legacy_token=True,
        )
        self._check_registration_complete(self._response_json_to_dict(response))
        # check that a proofing element was not written as the token is not mfa capable
        assert self.app.proofing_log.db_count() == 0

    def test_finish_register_ctap2(self) -> None:
        response = self._finish_register_key(
            client_data=CLIENT_DATA_JSON_2, attestation=ATTESTATION_OBJECT_2, state=STATE_2, cred_id=CREDENTIAL_ID_2
        )
        self._check_registration_complete(self._response_json_to_dict(response))
        # check that a proofing element was written as the token is mfa capable
        assert self.app.proofing_log.db_count() == 1

    def test_finish_register_ctap2_with_legacy_token(self) -> None:
        response = self._finish_register_key(
            client_data=CLIENT_DATA_JSON_2,
            attestation=ATTESTATION_OBJECT_2,
            state=STATE_2,
            cred_id=CREDENTIAL_ID_2,
            existing_legacy_token=True,
        )
        self._check_registration_complete(self._response_json_to_dict(response))
        # check that a proofing element was written as the token is mfa capable
        assert self.app.proofing_log.db_count() == 1

    def test_finish_register_ctap2_signup_authn(self) -> None:
        self.setup_signup_authn()
        response = self._finish_register_key(
            set_authn_action=False,
            client_data=CLIENT_DATA_JSON_2,
            attestation=ATTESTATION_OBJECT_2,
            state=STATE_2,
            cred_id=CREDENTIAL_ID_2,
        )
        self._check_registration_complete(self._response_json_to_dict(response))
        # check that a proofing element was written as the token is mfa capable
        assert self.app.proofing_log.db_count() == 1

    def test_finish_register_wrong_csrf(self) -> None:
        response = self._finish_register_key(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            cred_id=CREDENTIAL_ID,
            csrf="wrong-token",
        )
        data = self._response_json_to_dict(response)
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REGISTER_COMPLETE_FAIL")
        self.assertEqual(data["payload"]["error"]["csrf_token"], ["CSRF failed to validate"])

    def test_remove_ctap1(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
            mock_mfa=True,
        )

        user_token, response = self._remove(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            client_data_2=CLIENT_DATA_JSON_2,
            attestation_2=ATTESTATION_OBJECT_2,
            state_2=STATE_2,
        )
        self._check_removal(self._response_json_to_dict(response), user_token)

    def test_remove_ctap1_with_legacy_token(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
            mock_mfa=True,
        )

        user_token, response = self._remove(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            client_data_2=CLIENT_DATA_JSON_2,
            attestation_2=ATTESTATION_OBJECT_2,
            state_2=STATE_2,
            existing_legacy_token=True,
        )
        self._check_removal(self._response_json_to_dict(response), user_token)

    def test_remove_ctap2(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
            mock_mfa=True,
        )

        user_token, response = self._remove(
            client_data=CLIENT_DATA_JSON_2,
            attestation=ATTESTATION_OBJECT_2,
            state=STATE_2,
            client_data_2=CLIENT_DATA_JSON,
            attestation_2=ATTESTATION_OBJECT,
            state_2=STATE,
        )
        self._check_removal(self._response_json_to_dict(response), user_token)

    def test_remove_ctap2_legacy_token(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
            mock_mfa=True,
        )

        user_token, response = self._remove(
            client_data=CLIENT_DATA_JSON_2,
            attestation=ATTESTATION_OBJECT_2,
            state=STATE_2,
            client_data_2=CLIENT_DATA_JSON,
            attestation_2=ATTESTATION_OBJECT,
            state_2=STATE,
            existing_legacy_token=True,
        )
        self._check_removal(self._response_json_to_dict(response), user_token)

    def test_remove_wrong_csrf(self) -> None:
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
        )

        _, response = self._remove(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            client_data_2=CLIENT_DATA_JSON_2,
            attestation_2=ATTESTATION_OBJECT_2,
            state_2=STATE_2,
            csrf="wrong-csrf",
        )
        data = self._response_json_to_dict(response)
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REMOVE_FAIL")
        self.assertEqual(data["payload"]["error"]["csrf_token"], ["CSRF failed to validate"])

    @patch("fido_mds.FidoMetadataStore.verify_attestation", _apple_special_verify_attestation)
    def test_authenticator_information(self) -> None:
        authenticators = [YUBIKEY_4, YUBIKEY_5_NFC, MICROSOFT_SURFACE_1796, NEXUS_5, IPHONE_12, NONE_ATTESTATION]
        for authenticator in authenticators:
            self.app.logger.debug(f"Testing authenticator: {authenticator}")
            with self.app.test_request_context():
                authenticator_info = get_authenticator_information(
                    attestation=Attestation.from_base64(authenticator[0]).attestation_obj,
                    client_data=websafe_decode(authenticator[1]),
                )
            assert authenticator_info is not None
            assert authenticator_info.authenticator_id is not None
            assert authenticator_info.attestation_format is not None
            assert authenticator_info.user_present is not None
            assert authenticator_info.user_verified is not None

            with self.app.test_request_context():
                res = is_authenticator_mfa_approved(authenticator_info=authenticator_info)
                if authenticator in [YUBIKEY_4, YUBIKEY_5_NFC]:
                    # Yubikey 4 does not support any user verification we accept
                    # The test data for Yubikey 5 do not include user verification
                    assert res is False
                else:
                    assert res is True

            if authenticator not in [IPHONE_12, NONE_ATTESTATION]:
                # No metadata for Apple devices or none attestation
                assert authenticator_info.last_status_change
                assert (
                    self.app.fido_metadata_log.exists(
                        authenticator_id=authenticator_info.authenticator_id,
                        last_status_change=authenticator_info.last_status_change,
                    )
                    is True
                )

    def test_authenticator_information_backdoor(self) -> None:
        # setup magic cookie backdoor
        self.app.conf.magic_cookie_name = "magic-cookie"
        self.app.conf.magic_cookie = "magic"
        self.app.conf.environment = EduidEnvironment.dev
        cookie = dump_cookie(self.app.conf.magic_cookie_name, self.app.conf.magic_cookie)

        attestation_object = (
            "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgYveunFJbAigRE3KZ0jq8Av_fVO82NPR6"
            "YLxr-PTBeb8CICzfv9hjw8Y4uln8JlROLeCt64v7HggN_I_GcQItOTGrY3g1Y4FZAd8wggHbMIIBfaAD"
            "AgECAgEBMA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAG"
            "A1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUw"
            "HhcNMTcwNzE0MDI0MDAwWhcNNDIwNTA1MTE1NDE0WjBgMQswCQYDVQQGEwJVUzERMA8GA1UECgwIQ2hy"
            "b21pdW0xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xGjAYBgNVBAMMEUJhdGNoIENl"
            "cnRpZmljYXRlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjWF-ZclQjmS8xWc6yCpnmdo8FEZoLCWM"
            "Rj__31jf0vo-bDeLU9eVxKTf-0GZ7deGLyOrrwIDtLiRG6BWmZThAaMlMCMwEwYLKwYBBAGC5RwCAQEE"
            "BAMCBSAwDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAANJADBGAiEArKE7uJfWz1hGHaZmFOsVI-We"
            "_0InOV5a2iYTY0B3MeYCIQD3YgB3fZ6rblVLxFz6oThec-VjDLmoaBqjCV9XlHKjNmhhdXRoRGF0YVik"
            "xj7KDbeWdwEtucH8hAuBSeGOZxHTsdSGjUDkRxEYLMJFAAAAAQECAwQFBgcIAQIDBAUGBwgAIIDUjmjJ"
            "kYbHD_WHo4odto2cGXooDmjgi24AqMK2pXilpQECAyYgASFYIHOTuF0ClvfK2HL2mSy9qNDdcNzGqeor"
            "i69A4oXAE2DyIlggdDAxctibUevqhHEZbJ2rkxCogHE8k4Ma-F1R6k0zmFE"
        )
        client_data = (
            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiX2VqYS1vT3Itdk1hZDJpdnNSYnNS"
            "N09EUzVXdzAtNUg0QnQweVR0dzNSYyIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmRldi5lZHVp"
            "ZC5zZSIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
        )
        with self.app.test_request_context(headers={"Cookie": cookie}):
            authenticator_info = get_authenticator_information(
                attestation=Attestation.from_base64(attestation_object).attestation_obj,
                client_data=websafe_decode(client_data),
            )
        assert authenticator_info is not None

        with self.app.test_request_context():
            res = is_authenticator_mfa_approved(authenticator_info=authenticator_info)
        assert res is True

    def test_approved_security_keys(self) -> None:
        response = self.browser.get("/webauthn/approved-security-keys")
        self._check_success_response(response=response, type_="GET_WEBAUTHN_WEBAUTHN_APPROVED_SECURITY_KEYS_SUCCESS")

        assert response.json
        payload = response.json.get("payload")
        assert "next_update" in payload
        assert "entries" in payload
        assert len(payload["entries"]) > 0

        # test twice to test @cache
        response = self.browser.get("/webauthn/approved-security-keys")
        self._check_success_response(response=response, type_="GET_WEBAUTHN_WEBAUTHN_APPROVED_SECURITY_KEYS_SUCCESS")

        assert response.json
        payload = response.json.get("payload")
        assert "next_update" in payload
        assert "entries" in payload
        assert len(payload["entries"]) > 0

        # test no doubles
        unique_lowecase_entries = list({e.lower() for e in payload["entries"]})
        assert len(unique_lowecase_entries) == len(payload["entries"])
