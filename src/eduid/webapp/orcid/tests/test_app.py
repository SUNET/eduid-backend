import json
from collections.abc import Mapping
from typing import Any

import pytest
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.config.base import FrontendAction
from eduid.userdb.orcid import OidcAuthorization, OidcIdToken, Orcid
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.messages import AuthnStatusMsg
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.session.namespaces import OIDCState
from eduid.webapp.orcid.app import OrcidApp, init_orcid_app
from eduid.webapp.orcid.helpers import OrcidMsg


class MockResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text


class OrcidTests(EduidAPITestCase[OrcidApp]):
    """Base TestCase for those tests that need a full environment setup"""

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None, mocker: MockerFixture) -> None:
        self.mocker = mocker
        self.test_user_eppn = "hubba-bubba"

        self.oidc_id_token = OidcIdToken(
            iss="iss", sub="sub", aud=["aud"], exp=0, iat=0, nonce="nonce", auth_time=0, created_by="orcid"
        )

        self.oidc_authz = OidcAuthorization(
            access_token="access_token",
            token_type="token_type",
            id_token=self.oidc_id_token,
            expires_in=0,
            refresh_token="refresh_token",
            created_by="orcid",
        )
        self.orcid_element = Orcid(
            id="https://sandbox.orcid.org/0000-0000-0000-0000",
            name=None,
            given_name="Test",
            family_name="Testsson",
            is_verified=True,
            oidc_authz=self.oidc_authz,
            created_by="orcid",
        )

    def load_app(self, config: Mapping[str, Any]) -> OrcidApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_orcid_app("testing", config)

    @pytest.fixture(scope="class")
    def update_config(self, class_mocker: MockerFixture) -> dict[str, Any]:
        oidc_provider_config = {
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "userinfo_endpoint": "https://example.com/op/oauth/userinfo",
            "authorization_endpoint": "https://example.com/op/oauth/authorize",
            "token_endpoint": "https://example.com/op/oauth/token",
            "jwks_uri": "https://example.com/op/oauth/jwks",
            "claims_supported": ["family_name", "given_name", "name", "auth_time", "iss", "sub"],
            "scopes_supported": ["openid"],
            "subject_types_supported": ["public"],
            "response_types_supported": ["code"],
            "claims_parameter_supported": False,
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "issuer": "https://example.com/op/",
        }
        class_mocker.patch(
            "oic.oic.Client.http_request",
            return_value=MockResponse(200, json.dumps(oidc_provider_config)),
        )
        config = self._get_base_config()
        config.update(
            {
                "provider_configuration_info": {"issuer": "https://example.com/op/"},
                "client_registration_info": {"client_id": "test_client", "client_secret": "secret"},
                "userinfo_endpoint_method": "GET",
                "orcid_verify_redirect_url": "https://dashboard.example.com/",
                "frontend_action_authn_parameters": {
                    FrontendAction.CONNECT_ORCID.value: {
                        "finish_url": "https://dashboard.example.com/profile/ext-return/{app_name}/{authn_id}",
                    },
                },
            }
        )
        return config

    def _start_connect(self, eppn: str) -> TestResponse:
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            return client.post(
                "/connect-orcid",
                json={
                    "csrf_token": csrf_token,
                    "frontend_action": FrontendAction.CONNECT_ORCID.value,
                    "frontend_state": "test_state",
                },
            )

    def _get_authn_id_from_session(self) -> OIDCState:
        with self.browser.session_transaction() as sess:
            authn_ids = list(sess.orcid.rp.authns.keys())
            return authn_ids[-1]

    def _get_nonce_from_session(self, oidc_state: OIDCState) -> str:
        with self.browser.session_transaction() as sess:
            return sess.orcid.nonces[oidc_state]

    def mock_authorization_callback(
        self,
        state: str,
        nonce: str,
        userinfo: dict[str, Any],
    ) -> TestResponse:
        mock_auth_response = self.mocker.patch("oic.oic.Client.parse_response")
        mock_userinfo_request = self.mocker.patch("oic.oic.Client.do_user_info_request")
        mock_token_request = self.mocker.patch("oic.oic.Client.do_access_token_request")
        mock_auth_response.return_value = {
            "id_token": "id_token",
            "code": "code",
            "state": state,
        }

        mock_token_request.return_value = {
            "access_token": "access_token",
            "token_type": "token_type",
            "expires_in": 0,
            "refresh_token": "refresh_token",
            "id_token": {
                "nonce": nonce,
                "sub": "sub",
                "iss": "iss",
                "aud": ["aud"],
                "exp": 0,
                "iat": 0,
                "auth_time": 0,
                "acr": "acr",
                "amr": ["amr"],
                "azp": "azp",
            },
        }
        userinfo["sub"] = "sub"
        mock_userinfo_request.return_value = userinfo
        return self.browser.get(f"/authorization-response?id_token=id_token&state={state}")

    def test_authenticate(self) -> None:
        response = self._start_connect(self.test_user_eppn)
        assert response.status_code == 200
        payload = self.get_response_payload(response)
        assert "location" in payload
        assert payload["location"].startswith(self.app.conf.provider_configuration_info["issuer"])

    def test_oidc_flow(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self._start_connect(self.test_user_eppn)
        assert response.status_code == 200
        payload = self.get_response_payload(response)
        assert "location" in payload

        # Get state and nonce from session
        authn_id = self._get_authn_id_from_session()
        nonce = self._get_nonce_from_session(authn_id)

        # Fake callback from OP
        userinfo = {
            "id": "https://sandbox.orcid.org/0000-0000-0000-0000",
            "name": None,
            "given_name": "Test",
            "family_name": "Testsson",
        }
        callback_response = self.mock_authorization_callback(state=str(authn_id), nonce=nonce, userinfo=userinfo)
        assert callback_response.status_code == 302
        assert "/ext-return/" in callback_response.location

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.orcid is not None
        assert user.orcid.id == userinfo["id"]
        assert user.orcid.name == userinfo["name"]
        assert user.orcid.given_name == userinfo["given_name"]
        assert user.orcid.family_name == userinfo["family_name"]
        assert self.app.proofing_log.db_count() == 1

    def test_get_status_after_callback(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self._start_connect(self.test_user_eppn)
        assert response.status_code == 200

        authn_id = self._get_authn_id_from_session()
        nonce = self._get_nonce_from_session(authn_id)

        userinfo = {
            "id": "https://sandbox.orcid.org/0000-0000-0000-0000",
            "name": None,
            "given_name": "Test",
            "family_name": "Testsson",
        }
        callback_response = self.mock_authorization_callback(state=str(authn_id), nonce=nonce, userinfo=userinfo)
        assert callback_response.status_code == 302

        # Poll get-status with the authn_id from the callback
        with self.browser.session_transaction() as sess:
            csrf_token = sess.get_csrf_token()
        status_response = self.browser.post(
            "/get-status",
            json={"csrf_token": csrf_token, "authn_id": str(authn_id)},
        )
        self._check_success_response(status_response, type_="POST_ORCID_GET_STATUS_SUCCESS")
        status_payload = self.get_response_payload(status_response)
        assert status_payload["frontend_action"] == FrontendAction.CONNECT_ORCID.value
        assert status_payload["frontend_state"] == "test_state"
        assert status_payload["method"] == "orcid"
        assert status_payload["error"] is False
        assert status_payload["status"] == OrcidMsg.authz_success.value

    def test_get_status_not_found(self) -> None:
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            response = client.post(
                "/get-status",
                json={"csrf_token": csrf_token, "authn_id": "nonexistent"},
            )
        self._check_error_response(response, type_="POST_ORCID_GET_STATUS_FAIL", msg=AuthnStatusMsg.not_found)

    def test_get_orcid(self) -> None:
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        proofing_user = ProofingUser.from_user(user, self.app.private_userdb)
        proofing_user.orcid = self.orcid_element
        self.request_user_sync(proofing_user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/")
        expected_payload = {
            "orcid": {
                "id": self.orcid_element.id,
                "given_name": self.orcid_element.given_name,
                "family_name": self.orcid_element.family_name,
            }
        }
        self._check_success_response(response, type_="GET_ORCID_SUCCESS", payload=expected_payload)

    def test_remove_orcid(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        proofing_user = ProofingUser.from_user(user, self.app.private_userdb)
        proofing_user.orcid = self.orcid_element
        self.request_user_sync(proofing_user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/")
        self._check_success_response(response, type_="GET_ORCID_SUCCESS")

        csrf_token = self.get_response_payload(response)["csrf_token"]
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.post(
                "/remove", data=json.dumps({"csrf_token": csrf_token}), content_type=self.content_type_json
            )
        self._check_success_response(response, type_="POST_ORCID_REMOVE_SUCCESS")

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.orcid is None

    def test_already_connected(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        proofing_user = ProofingUser.from_user(user, self.app.private_userdb)
        proofing_user.orcid = self.orcid_element
        self.request_user_sync(proofing_user)

        response = self._start_connect(self.test_user_eppn)
        self._check_error_response(response, type_="POST_ORCID_CONNECT_ORCID_FAIL", msg=OrcidMsg.already_connected)
