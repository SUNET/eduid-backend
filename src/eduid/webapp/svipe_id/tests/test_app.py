# -*- coding: utf-8 -*-
from unittest.mock import patch

from flask import url_for

from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.svipe_id.app import svipe_id_init_app

__author__ = "lundberg"


class SvipeIdTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        super(SvipeIdTests, self).setUp()

        self.oidc_provider_config = {
            "issuer": "https://example.com/op/",
            "authorization_endpoint": "https://example.com/op/authorize",
            "token_endpoint": "https://example.com/op/token",
            "userinfo_endpoint": "https://example.com/op/userinfo",
            "jwks_uri": "https://example.com/op/keys",
            "registration_endpoint": "https://example.com/op/clients",
            "scopes_supported": ["openid", "profile", "email", "phone", "document", "document_full"],
            "response_types_supported": [
                "code",
                "token",
                "id_token",
                "id_token token",
                "code id_token",
                "code token",
                "code id_token token",
                "none",
            ],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "revocation_endpoint": "https://example.com/op/token/revoke",
            "end_session_endpoint": "https://example.com/op/logout",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "claims_supported": [
                "iss",
                "ver",
                "sub",
                "aud",
                "iat",
                "exp",
                "jti",
                "auth_time",
                "amr",
                "idp",
                "nonce",
                "at_hash",
                "c_hashname",
                "given_name",
                "family_name",
                "email",
                "email_verified",
                "phone_number",
                "phone_number_verified",
                "gender",
                "birthdate",
                "updated_at",
                "locale",
                "com.svipe:svipeid",
                "com.svipe:document_portrait",
                "com.svipe:document_nationality",
                "com.svipe:document_nationality_en",
                "com.svipe:document_type",
                "com.svipe:document_type_sdn",
                "com.svipe:document_type_sdn_en",
                "com.svipe:document_number",
                "com.svipe:document_issuing_country",
                "com.svipe:document_issuing_country_en",
                "com.svipe:document_expiry_date",
                "com.svipe:document_administrative_number",
            ],
            "backchannel_logout_supported": True,
            "backchannel_logout_session_supported": True,
            "frontchannel_logout_supported": True,
            "frontchannel_logout_session_supported": True,
            "claims_parameter_supported": True,
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "request_object_signing_alg_values_supported": ["RS256"],
            "userinfo_signing_alg_values_supported": ["RS256"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "acr_values_supported": ["face_present", "document_present", "face_and_document_present"],
        }

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return svipe_id_init_app("testing", config)

    def update_config(self, config):
        config.update(
            {
                "svipe_client": {
                    "client_id": "test_client_id",
                    "client_secret": "test_client_secret",
                    "issuer": "https://issuer.example.com",
                    "acr_values": ["face_present"],
                    "scopes": ["openid", "document"],
                },
                "frontend_action_finish_url": {
                    "svipeidVerifyIdentity": "https://dashboard.example.com/profile/ext-return/{app_name}/{authn_id}",
                },
            }
        )
        return config

    def tearDown(self):
        super(SvipeIdTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    def test_app_starts(self):
        assert self.app.conf.app_name == "testing"

    def test_authenticate(self):
        response = self.browser.get("/")
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user.eppn) as browser:
            response = browser.get("/")
        self._check_success_response(response, type_="GET_SVIPE_ID_SUCCESS")

    @patch("authlib.integrations.base_client.sync_app.OAuth2Mixin.load_server_metadata")
    def test_create_authn_url(self, mock_metadata):
        mock_metadata.return_value = self.oidc_provider_config

        with self.app.test_request_context():
            endpoint = url_for("svipe_id.verify_identity")

        with self.session_cookie(self.browser, self.test_user.eppn) as client:
            with client.session_transaction() as sess:
                csrf_token = sess.get_csrf_token()
            data = {
                "csrf_token": csrf_token,
                "method": "svipe_id",
                "frontend_action": "svipeidVerifyIdentity",
                "frontend_state": "test_state",
            }
            response = client.post(endpoint, json=data)
            assert response.status_code == 200
            self._check_success_response(response, type_="POST_SVIPE_ID_VERIFY_IDENTITY_SUCCESS")
            assert response.json["payload"]["location"].startswith("https://example.com/op/authorize")
