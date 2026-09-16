import json
import uuid
from collections.abc import Iterator
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from pytest_mock import MockerFixture
from werkzeug.test import TestResponse

from eduid.common.clients.oidc_client.base import OidcRpClient, OidcRpError
from eduid.common.clients.oidc_client.testing import FakeOidcRpClient
from eduid.common.config.base import FrontendAction
from eduid.userdb.orcid import OidcAuthorization, OidcIdToken, Orcid
from eduid.userdb.proofing import ProofingUser
from eduid.webapp.common.api.messages import AuthnStatusMsg
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.session.namespaces import OIDCState
from eduid.webapp.orcid.app import OrcidApp, init_orcid_app
from eduid.webapp.orcid.helpers import OrcidMsg


class OrcidTests(EduidAPITestCase[OrcidApp]):
    """Base TestCase for those tests that need a full environment setup"""

    @pytest.fixture(autouse=True)
    def setup(self, setup_api: None, mocker: MockerFixture) -> Iterator[None]:
        self.mocker = mocker
        self.test_user_eppn = "hubba-bubba"

        # Save/restore the real oidc_client set up by the app, since some tests replace it with a
        # FakeOidcRpClient and the app is shared (class-scoped) across all tests in this class.
        self._real_oidc_client: OidcRpClient = self.app.oidc_client

        self.oidc_provider_config = {
            "issuer": "https://example.com/op/",
            "authorization_endpoint": "https://example.com/op/oauth/authorize",
            "token_endpoint": "https://example.com/op/oauth/token",
            "userinfo_endpoint": "https://example.com/op/oauth/userinfo",
            "jwks_uri": "https://example.com/op/oauth/jwks",
            "claims_supported": ["family_name", "given_name", "name", "auth_time", "iss", "sub"],
            "scopes_supported": ["openid"],
            "subject_types_supported": ["public"],
            "response_types_supported": ["code"],
            "claims_parameter_supported": False,
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

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

        yield

        self.app.oidc_client = self._real_oidc_client

    @classmethod
    def load_app(cls, config: dict[str, Any]) -> OrcidApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_orcid_app("testing", config)

    @pytest.fixture(scope="class")
    @classmethod
    def update_config(cls) -> dict[str, Any]:
        config = cls._get_base_config()
        config.update(
            {
                "orcid_client": {
                    "client_id": "test_client",
                    "client_secret": "secret",
                    "issuer": "https://example.com/op/",
                },
                "frontend_action_authn_parameters": {
                    FrontendAction.CONNECT_ORCID.value: {
                        "finish_url": "https://dashboard.example.com/profile/ext-return/{app_name}/{authn_id}",
                    },
                },
            }
        )
        return config

    def _install_fake_oidc_client(self) -> FakeOidcRpClient:
        fake_client = FakeOidcRpClient(
            authorization_endpoint=str(self.oidc_provider_config["authorization_endpoint"]),
            state=str(uuid.uuid4()),
            nonce=str(uuid.uuid4()),
        )
        self.app.oidc_client = fake_client
        return fake_client

    def _start_connect(self, eppn: str) -> TestResponse:
        self._install_fake_oidc_client()
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

    def _start_connect_with_real_oidc_client(self, eppn: str) -> TestResponse:
        """Like _start_connect, but exercises the real (authlib-backed) oidc_client instead of a fake one."""
        mock_metadata = self.mocker.patch("authlib.integrations.base_client.sync_app.OAuth2Mixin.load_server_metadata")
        mock_metadata.return_value = self.oidc_provider_config

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

    def mock_authorization_callback(
        self,
        state: str,
        nonce: str,
        userinfo: dict[str, Any],
        aud: str | list[str] | None = None,
    ) -> TestResponse:
        fake_client = self.app.oidc_client
        assert isinstance(fake_client, FakeOidcRpClient)
        id_token_claims = {
            "nonce": nonce,
            "sub": "sub",
            "iss": "iss",
            "aud": aud if aud is not None else ["aud"],
            "exp": 0,
            "iat": 0,
            "auth_time": 0,
        }
        fake_client.token_response = {
            "access_token": "access_token",
            "token_type": "token_type",
            "expires_in": 0,
            "refresh_token": "refresh_token",
            "userinfo": id_token_claims,
        }
        userinfo = dict(userinfo)
        userinfo["sub"] = "sub"
        fake_client.userinfo_response = userinfo
        return self.browser.get(f"/authorization-response?state={state}&code=mock_code")

    def test_authenticate(self) -> None:
        """
        Regression test for the authlib wiring done in init_oidc_rp_client/AuthlibOidcRpClient,
        exercising the real (authlib-backed) oidc_client rather than FakeOidcRpClient.
        """
        response = self._start_connect_with_real_oidc_client(self.test_user_eppn)
        assert response.status_code == HTTPStatus.OK
        payload = self.get_response_payload(response)
        assert "location" in payload
        location = payload["location"]
        assert location.startswith("https://example.com/op/oauth/authorize")

        query = parse_qs(urlparse(location).query)
        assert query["response_type"] == ["code"]
        assert query["client_id"] == ["test_client"]
        assert query["redirect_uri"] == ["http://test.localhost/authorization-response"]
        assert query["scope"] == ["openid"]
        assert query["claims"] == [json.dumps({"userinfo": {"id": None}})]
        assert len(query["state"][0]) > 0
        # ORCID does not support PKCE - no code_challenge should be sent
        assert "code_challenge" not in query
        assert "code_challenge_method" not in query

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with client.session_transaction() as sess:
                assert len(sess.orcid.rp.authlib_cache) > 0

    def test_oidc_flow(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self._start_connect(self.test_user_eppn)
        assert response.status_code == 200
        payload = self.get_response_payload(response)
        assert "location" in payload

        # Get state from session
        authn_id = self._get_authn_id_from_session()

        # Fake callback from OP
        userinfo = {
            "id": "https://sandbox.orcid.org/0000-0000-0000-0000",
            "name": None,
            "given_name": "Test",
            "family_name": "Testsson",
        }
        callback_response = self.mock_authorization_callback(state=str(authn_id), nonce="nonce", userinfo=userinfo)
        assert callback_response.status_code == 302
        assert "/ext-return/" in callback_response.location

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.orcid is not None
        assert user.orcid.id == userinfo["id"]
        assert user.orcid.name == userinfo["name"]
        assert user.orcid.given_name == userinfo["given_name"]
        assert user.orcid.family_name == userinfo["family_name"]
        assert self.app.proofing_log.db_count() == 1

    def test_oidc_flow_string_aud(self, mocker: MockerFixture) -> None:
        """ORCID issues 'aud' as a bare string, not a list - make sure that is normalized correctly."""
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self._start_connect(self.test_user_eppn)
        assert response.status_code == 200

        authn_id = self._get_authn_id_from_session()

        userinfo = {
            "id": "https://sandbox.orcid.org/0000-0000-0000-0000",
            "name": None,
            "given_name": "Test",
            "family_name": "Testsson",
        }
        callback_response = self.mock_authorization_callback(
            state=str(authn_id), nonce="nonce", userinfo=userinfo, aud="aud"
        )
        assert callback_response.status_code == 302
        assert "/ext-return/" in callback_response.location

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.orcid is not None
        assert user.orcid.oidc_authz.id_token.aud == ["aud"]

    def test_oidc_flow_fetch_token_error(self) -> None:
        response = self._start_connect(self.test_user_eppn)
        assert response.status_code == 200
        authn_id = self._get_authn_id_from_session()

        fake_client = self.app.oidc_client
        assert isinstance(fake_client, FakeOidcRpClient)
        fake_client.raise_on_fetch_token = OidcRpError("token endpoint failed")

        callback_response = self.browser.get(f"/authorization-response?state={authn_id}&code=mock_code")
        assert callback_response.status_code == 302

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            status_response = client.post(
                "/get-status",
                json={"csrf_token": csrf_token, "authn_id": str(authn_id)},
            )
        status_payload = self.get_response_payload(status_response)
        assert status_payload["error"] is True
        assert status_payload["status"] == OrcidMsg.authz_error.value

    def test_get_status_after_callback(self, mocker: MockerFixture) -> None:
        mock_request_user_sync = mocker.patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self._start_connect(self.test_user_eppn)
        assert response.status_code == 200

        authn_id = self._get_authn_id_from_session()

        userinfo = {
            "id": "https://sandbox.orcid.org/0000-0000-0000-0000",
            "name": None,
            "given_name": "Test",
            "family_name": "Testsson",
        }
        callback_response = self.mock_authorization_callback(state=str(authn_id), nonce="nonce", userinfo=userinfo)
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
