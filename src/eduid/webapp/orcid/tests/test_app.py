import json
from collections.abc import Mapping
from typing import Any
from unittest.mock import MagicMock, patch

from eduid.userdb.orcid import OidcAuthorization, OidcIdToken, Orcid
from eduid.userdb.proofing import ProofingUser
from eduid.userdb.proofing.state import OrcidProofingState
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.orcid.app import OrcidApp, init_orcid_app

__author__ = "lundberg"


class OrcidTests(EduidAPITestCase[OrcidApp]):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self, *args: Any, **kwargs: Any):
        self.test_user_eppn = "hubba-bubba"
        self.oidc_provider_config = {
            "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "userinfo_endpoint": "https://https://example.com/op/oauth/userinfo",
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

        class MockResponse:
            def __init__(self, status_code: int, text: str):
                self.status_code = status_code
                self.text = text

        self.oidc_provider_config_response = MockResponse(200, json.dumps(self.oidc_provider_config))

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

        super().setUp(*args, **kwargs)

    def load_app(self, config: Mapping[str, Any]) -> OrcidApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        with patch("oic.oic.Client.http_request") as mock_response:
            mock_response.return_value = self.oidc_provider_config_response
            return init_orcid_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "provider_configuration_info": {"issuer": "https://example.com/op/"},
                "client_registration_info": {"client_id": "test_client", "client_secret": "secret"},
                "userinfo_endpoint_method": "GET",
                "orcid_verify_redirect_url": "https://dashboard.example.com/",
            }
        )
        return config

    @patch("oic.oic.Client.parse_response")
    @patch("oic.oic.Client.do_user_info_request")
    @patch("oic.oic.Client.do_access_token_request")
    def mock_authorization_response(
        self,
        proofing_state: OrcidProofingState,
        userinfo: dict[str, Any],
        mock_token_request: MagicMock,
        mock_userinfo_request: MagicMock,
        mock_auth_response: MagicMock,
    ):
        mock_auth_response.return_value = {
            "id_token": "id_token",
            "code": "code",
            "state": proofing_state.state,
        }

        mock_token_request.return_value = {
            "access_token": "access_token",
            "token_type": "token_type",
            "expires_in": 0,
            "refresh_token": "refresh_token",
            "id_token": {
                "nonce": proofing_state.nonce,
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
        return self.browser.get(f"/authorization-response?id_token=id_token&state={proofing_state.state}")

    def test_authenticate(self):
        response = self.browser.get("/authorize")
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        self.assertTrue(response.location.startswith(self.app.conf.authn_service_url))
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/authorize")
        self.assertEqual(response.status_code, 302)  # Authenticated request redirected to OP
        self.assertTrue(response.location.startswith(self.app.conf.provider_configuration_info["issuer"]))

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_oidc_flow(self, mock_request_user_sync: MagicMock):
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get("/authorize")
        self.assertEqual(response.status_code, 302)  # Authenticated request redirected to OP

        # Fake callback from OP
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        assert proofing_state is not None
        userinfo = {
            "id": "https://sandbox.orcid.org/0000-0000-0000-0000",
            "name": None,
            "given_name": "Test",
            "family_name": "Testsson",
        }
        self.mock_authorization_response(proofing_state, userinfo)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.orcid is not None
        self.assertEqual(user.orcid.id, userinfo["id"])
        self.assertEqual(user.orcid.name, userinfo["name"])
        self.assertEqual(user.orcid.given_name, userinfo["given_name"])
        self.assertEqual(user.orcid.family_name, userinfo["family_name"])
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    def test_get_orcid(self):
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

    @patch("eduid.common.rpc.am_relay.AmRelay.request_user_sync")
    def test_remove_orcid(self, mock_request_user_sync: MagicMock):
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
        self.assertEqual(user.orcid, None)
