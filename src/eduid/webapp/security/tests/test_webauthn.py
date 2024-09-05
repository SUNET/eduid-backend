import base64
import json
from typing import Any, Mapping, Optional
from unittest.mock import patch

from fido_mds import FidoMetadataStore

from fido2.webauthn import AttestationObject, AuthenticatorAttachment, CollectedClientData
from werkzeug.http import dump_cookie

from eduid.common.config.base import EduidEnvironment, FrontendAction
from eduid.userdb.credentials import U2F, FidoCredential, Webauthn
from eduid.webapp.common.api.testing import EduidAPITestCase
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
from fido_mds.tests.data import IPHONE_12, MICROSOFT_SURFACE_1796, NEXUS_5, YUBIKEY_4, YUBIKEY_5_NFC, NONE_ATTESTATION

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
STATE_2 = {"challenge": "iW6wn2xAYUfBueKvhIyTsB6YRsQz9OIwaPfw1ZoCtNY", "user_verification": "discouraged"}

ATTESTATION_OBJECT_2 = (
    b"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhANNvwZhaTvdSujKW3pUCfeYB_ABjCo2X"
    b"dg8e5RowhAgZAiBmj8DH71y46Rg9W67BTG1MuBmaycK7osVy6g_ppmJGiGN4NWOBWQLBMIICvTCCAaWg"
    b"AwIBAgIEHo-HNDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2Vy"
    b"aWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMC"
    b"U0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEn"
    b"MCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNTEyNzIyNzQwMFkwEwYHKoZIzj0CAQYIKoZIzj0D"
    b"AQcDQgAEqHn4IzjtFJS6wHBLzH_GY9GycXFZdiQxAcdgURXXwVKeKBwcZzItOEtc1V3T6YGNX9hcIq8y"
    b"bgxk_CCv4z8jZqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC"
    b"5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQL8BXn4ETR-qxFrtajbkgKjAMBgNVHRMBAf8EAjAA"
    b"MA0GCSqGSIb3DQEBCwUAA4IBAQCGk_9i3w1XedR0jX_I0QInMYqOWA5qOlfBCOlOA8OFaLNmiU_OViS-"
    b"Sj79fzQRiz2ZN0P3kqGYkWDI_JrgsE49-e4V4-iMBPyCqNy_WBjhCNzCloV3rnn_ZiuUc0497EWXMF1z"
    b"5uVe4r65zZZ4ygk15TPrY4-OJvq7gXzaRB--mDGDKuX24q2ZL56720xiI4uPjXq0gdbTJjvNv55KV1UD"
    b"cJiK1YE0QPoDLK22cjyt2PjXuoCfdbQ8_6Clua3RQjLvnZ4UgSY4IzxMpKhzufismOMroZFnYG4VkJ_N"
    b"20ot_72uRiAkn5pmRqyB5IMtERn-v6pzGogtolp3gn1G0ZAXaGF1dGhEYXRhWMTc9wRxJipqDOIk0QJj"
    b"FIEoxHTUnimbJIcg88Mz7jZh00EAAAAEL8BXn4ETR-qxFrtajbkgKgBAz6lLs6rFz6zm4IH73RUcSaVb"
    b"C5v4-J6j8HGS-VwPYIhyYUi6d1mxHYZPuehFrC5-r4ZmFqd7gpMdoJCo4H1bT6UBAgMmIAEhWCBTzCFk"
    b"fHJcW7ny9bUS4h8YqUadyw0q4kg91vgkScDscCJYICsxt49Uv09cN4OSw93GtjMLxgoaIfFhAK0vd9WL"
    b"vOY8"
)

CLIENT_DATA_JSON_2 = (
    b"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaVc2d24yeEFZVWZCdWVLdmhJeVRz"
    b"QjZZUnNRejlPSXdhUGZ3MVpvQ3ROWSIsIm9yaWdpbiI6Imh0dHBzOi8vZGFzaGJvYXJkLmVkdWlkLmRv"
    b"Y2tlciIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
)

CREDENTIAL_ID_2 = (
    "7bad3b59fa16e9e8840e2fd15c026a3c9a7d2877fd7d97c25a3b3158d1a9cba1e14b7c9913915"
    "f912366c18bd06bc9e903bc779409a8a7c749511e2b44e54c88"
)


class SecurityWebauthnTests(EduidAPITestCase):
    app: SecurityApp

    def setUp(self):
        super().setUp()
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
        _client_data = client_data + (b"=" * (len(client_data) % 4))
        client_data_obj = CollectedClientData(base64.urlsafe_b64decode(_client_data))
        _attestation = attestation + (b"=" * (len(attestation) % 4))
        att_obj = AttestationObject(base64.urlsafe_b64decode(_attestation))
        server = get_webauthn_server(rp_id=self.app.conf.fido2_rp_id, rp_name=self.app.conf.fido2_rp_name)
        auth_data = server.register_complete(state, client_data_obj, att_obj)
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

    def _check_session_state(self, client):
        with client.session_transaction() as sess:
            assert isinstance(sess, EduidSession)
            assert sess.security.webauthn_registration is not None
            webauthn_state = sess.security.webauthn_registration.webauthn_state
        assert webauthn_state["user_verification"] == "discouraged"
        assert "challenge" in webauthn_state

    def _check_registration_begun(self, data):
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_SUCCESS")
        self.assertIn("registration_data", data["payload"])
        self.assertIn("csrf_token", data["payload"])

    def _check_registration_complete(self, data):
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REGISTER_COMPLETE_SUCCESS")
        self.assertTrue(len(data["payload"]["credentials"]) > 0)
        self.assertEqual(data["payload"]["message"], "security.webauthn_register_success")

    def _check_removal(self, data, user_token):
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REMOVE_SUCCESS")
        self.assertIsNotNone(data["payload"]["credentials"])
        for credential in data["payload"]["credentials"]:
            self.assertIsNotNone(credential)
            self.assertNotEqual(credential["key"], user_token.key)

    # parameterized test methods
    def _begin_register_key(
        self,
        other: Optional[str] = None,
        authenticator: str = "cross-platform",
        existing_legacy_token: bool = False,
        csrf: Optional[str] = None,
        check_session: bool = True,
    ):
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

        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.ADD_SECURITY_KEY_AUTHN,
            force_mfa=force_mfa,
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

            return json.loads(response2.data)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _finish_register_key(
        self,
        mock_request_user_sync: Any,
        client_data: bytes,
        attestation: bytes,
        state: dict,
        cred_id: bytes,
        existing_legacy_token: bool = False,
        csrf: Optional[str] = None,
    ):
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

        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.ADD_SECURITY_KEY_AUTHN,
            force_mfa=force_mfa,
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
                        "attestationObject": attestation.decode(),
                        "clientDataJSON": client_data.decode(),
                        "credentialId": cred_id,
                        "description": "dummy description",
                    }
            response2 = client.post(
                "/webauthn/register/complete", data=json.dumps(data), content_type=self.content_type_json
            )
            return json.loads(response2.data)

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def _remove(
        self,
        mock_request_user_sync: Any,
        client_data: bytes,
        attestation: bytes,
        state: dict,
        client_data_2: bytes,
        attestation_2: bytes,
        state_2: dict,
        existing_legacy_token: bool = False,
        csrf: Optional[str] = None,
    ):
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
            return user_token, json.loads(response2.data)

    def _apple_special_verify_attestation(self: FidoMetadataStore, attestation: Attestation, client_data: bytes) -> bool:
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

    def test_begin_no_login(self):
        response = self.browser.get("/webauthn/register/begin")
        self.assertEqual(response.status_code, 302)  # Redirect to authn service

    def test_begin_register_first_key(self):
        data = self._begin_register_key()
        self._check_registration_begun(data)

    def test_begin_register_first_key_with_legacy_token(self):
        data = self._begin_register_key(existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_2nd_key_ater_ctap1(self):
        data = self._begin_register_key(other="ctap1")
        self._check_registration_begun(data)

    def test_begin_register_2nd_key_ater_ctap1_with_legacy_token(self):
        data = self._begin_register_key(other="ctap1", existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_2nd_key_ater_ctap2(self):
        data = self._begin_register_key(other="ctap2")
        self._check_registration_begun(data)

    def test_begin_register_2nd_key_ater_ctap2_with_legacy_token(self):
        data = self._begin_register_key(other="ctap2", existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_first_device(self):
        data = self._begin_register_key(authenticator="platform")
        self._check_registration_begun(data)

    def test_begin_register_first_device_with_legacy_token(self):
        data = self._begin_register_key(authenticator="platform", existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_2nd_device_ater_ctap1(self):
        data = self._begin_register_key(other="ctap1", authenticator="platform")
        self._check_registration_begun(data)

    def test_begin_register_2nd_device_ater_ctap1_with_legacy_token(self):
        data = self._begin_register_key(other="ctap1", authenticator="platform", existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_2nd_device_ater_ctap2(self):
        data = self._begin_register_key(other="ctap2", authenticator="platform")
        self._check_registration_begun(data)

    def test_begin_register_2nd_device_ater_ctap2_with_legacy_token(self):
        data = self._begin_register_key(other="ctap2", authenticator="platform", existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_wrong_csrf_token(self):
        data = self._begin_register_key(csrf="wrong-token", check_session=False)
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_FAIL")
        self.assertEqual(data["payload"]["error"]["csrf_token"], ["CSRF failed to validate"])

    def test_finish_register_ctap1(self):
        data = self._finish_register_key(
            client_data=CLIENT_DATA_JSON, attestation=ATTESTATION_OBJECT, state=STATE, cred_id=CREDENTIAL_ID
        )
        self._check_registration_complete(data)
        # check that a proofing element was not written as the token is not mfa capable
        assert self.app.proofing_log.db_count() == 0

    def test_finish_register_ctap1_with_legacy_token(self):
        data = self._finish_register_key(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            cred_id=CREDENTIAL_ID,
            existing_legacy_token=True,
        )
        self._check_registration_complete(data)
        # check that a proofing element was not written as the token is not mfa capable
        assert self.app.proofing_log.db_count() == 0

    def test_finish_register_ctap2(self):
        data = self._finish_register_key(
            client_data=CLIENT_DATA_JSON_2, attestation=ATTESTATION_OBJECT_2, state=STATE_2, cred_id=CREDENTIAL_ID_2
        )
        self._check_registration_complete(data)
        # check that a proofing element was written as the token is mfa capable
        assert self.app.proofing_log.db_count() == 1

    def test_finish_register_ctap2_with_legacy_token(self):
        data = self._finish_register_key(
            client_data=CLIENT_DATA_JSON_2,
            attestation=ATTESTATION_OBJECT_2,
            state=STATE_2,
            cred_id=CREDENTIAL_ID_2,
            existing_legacy_token=True,
        )
        self._check_registration_complete(data)
        # check that a proofing element was written as the token is mfa capable
        assert self.app.proofing_log.db_count() == 1

    def test_finish_register_wrong_csrf(self):
        data = self._finish_register_key(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            cred_id=CREDENTIAL_ID,
            csrf="wrong-token",
        )
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REGISTER_COMPLETE_FAIL")
        self.assertEqual(data["payload"]["error"]["csrf_token"], ["CSRF failed to validate"])

    def test_remove_ctap1(self):
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
            force_mfa=True,
        )

        user_token, data = self._remove(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            client_data_2=CLIENT_DATA_JSON_2,
            attestation_2=ATTESTATION_OBJECT_2,
            state_2=STATE_2,
        )
        self._check_removal(data, user_token)

    def test_remove_ctap1_with_legacy_token(self):
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
            force_mfa=True,
        )

        user_token, data = self._remove(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            client_data_2=CLIENT_DATA_JSON_2,
            attestation_2=ATTESTATION_OBJECT_2,
            state_2=STATE_2,
            existing_legacy_token=True,
        )
        self._check_removal(data, user_token)

    def test_remove_ctap2(self):
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
            force_mfa=True,
        )

        user_token, data = self._remove(
            client_data=CLIENT_DATA_JSON_2,
            attestation=ATTESTATION_OBJECT_2,
            state=STATE_2,
            client_data_2=CLIENT_DATA_JSON,
            attestation_2=ATTESTATION_OBJECT,
            state_2=STATE,
        )
        self._check_removal(data, user_token)

    def test_remove_ctap2_legacy_token(self):
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
            force_mfa=True,
        )

        user_token, data = self._remove(
            client_data=CLIENT_DATA_JSON_2,
            attestation=ATTESTATION_OBJECT_2,
            state=STATE_2,
            client_data_2=CLIENT_DATA_JSON,
            attestation_2=ATTESTATION_OBJECT,
            state_2=STATE,
            existing_legacy_token=True,
        )
        self._check_removal(data, user_token)

    def test_remove_wrong_csrf(self):
        self.set_authn_action(
            eppn=self.test_user_eppn,
            frontend_action=FrontendAction.REMOVE_SECURITY_KEY_AUTHN,
        )

        _, data = self._remove(
            client_data=CLIENT_DATA_JSON,
            attestation=ATTESTATION_OBJECT,
            state=STATE,
            client_data_2=CLIENT_DATA_JSON_2,
            attestation_2=ATTESTATION_OBJECT_2,
            state_2=STATE_2,
            csrf="wrong-csrf",
        )
        self.assertEqual(data["type"], "POST_WEBAUTHN_WEBAUTHN_REMOVE_FAIL")
        self.assertEqual(data["payload"]["error"]["csrf_token"], ["CSRF failed to validate"])

    @patch("fido_mds.FidoMetadataStore.verify_attestation", _apple_special_verify_attestation)
    def test_authenticator_information(self):        
        authenticators = [YUBIKEY_4, YUBIKEY_5_NFC, MICROSOFT_SURFACE_1796, NEXUS_5, IPHONE_12, NONE_ATTESTATION]
        for authenticator in authenticators:
            with self.app.test_request_context():
                authenticator_info = get_authenticator_information(
                    attestation=authenticator[0], client_data=authenticator[1]
                )
            assert authenticator_info is not None
            assert authenticator_info.authenticator_id is not None
            assert authenticator_info.attestation_format is not None
            assert authenticator_info.user_present is not None
            assert authenticator_info.user_verified is not None

            with self.app.test_request_context():
                res = is_authenticator_mfa_approved(authenticator_info=authenticator_info)
                if authenticator in [YUBIKEY_4, NONE_ATTESTATION]:
                    # Yubikey 4 does not support any user verification we accept
                    # None attestations cannot be verified to support anything we accept
                    assert res is False
                else:
                    assert res is True

            if authenticator not in [IPHONE_12, NONE_ATTESTATION]:
                # No metadata for Apple devices or none attestation
                assert (
                    self.app.fido_metadata_log.exists(
                        authenticator_id=authenticator_info.authenticator_id,
                        last_status_change=authenticator_info.last_status_change,
                    )
                    is True
                )

    def test_authenticator_information_backdoor(self):
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
            authenticator_info = get_authenticator_information(attestation=attestation_object, client_data=client_data)
        assert authenticator_info is not None

        with self.app.test_request_context():
            res = is_authenticator_mfa_approved(authenticator_info=authenticator_info)
        assert res is False

    def test_approved_security_keys(self):
        response = self.browser.get("/webauthn/approved-security-keys")
        self._check_success_response(response=response, type_="GET_WEBAUTHN_WEBAUTHN_APPROVED_SECURITY_KEYS_SUCCESS")

        payload = response.json.get("payload")
        assert "next_update" in payload
        assert "entries" in payload
        assert len(payload["entries"]) > 0

        # test twice to test @cache
        response = self.browser.get("/webauthn/approved-security-keys")
        self._check_success_response(response=response, type_="GET_WEBAUTHN_WEBAUTHN_APPROVED_SECURITY_KEYS_SUCCESS")

        payload = response.json.get("payload")
        assert "next_update" in payload
        assert "entries" in payload
        assert len(payload["entries"]) > 0

        # test no doubles
        unique_lowecase_entries = list(set(e.lower() for e in payload["entries"]))
        assert len(unique_lowecase_entries) == len(payload["entries"])
