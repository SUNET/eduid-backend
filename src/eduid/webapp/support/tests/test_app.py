from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from werkzeug.exceptions import HTTPException

from eduid.common.config.base import FrontendAction
from eduid.common.misc.timeutil import utc_now
from eduid.userdb.element import ElementKey
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.testing import CSRFTestClient, EduidAPITestCase
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.session.namespaces import SP_AuthnRequest
from eduid.webapp.support.app import SupportApp, support_init_app

__author__ = "lundberg"


class SupportAppTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    app: SupportApp

    def setUp(self, config: SetupConfig | None = None) -> None:
        super().setUp(config=config)

        self.test_user_eppn = "hubba-bubba"
        self.client = self.app.test_client()

    def load_app(self, config: Mapping[str, Any]) -> SupportApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return support_init_app("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "support_personnel": ["hubba-bubba"],
                "authn_service_url_logout": "https://localhost/logout",
                "eduid_static_url": "https://testing.eduid.se/static/",
            }
        )
        return config

    # LOGIN TESTS:
    # 1 - test without login
    # 2 - test with login but not MFA
    # 3 - test with login and MFA

    # SEARCH TESTS:
    # A - search existing user
    # B - search non existing user

    def set_authn_action_custom(
        self,
        eppn: str,
        frontend_action: FrontendAction,
        post_authn_action: AuthnAcsAction = AuthnAcsAction.login,
        age: timedelta = timedelta(seconds=30),
        finish_url: str | None = None,
        mock_mfa: bool = False,
        credentials_used: list[ElementKey] | None = None,
    ) -> CSRFTestClient:
        if not finish_url:
            finish_url = "https://example.com/ext-return/{app_name}/{authn_id}"

        if credentials_used is None:
            credentials_used = []

        if mock_mfa:
            credentials_used = [ElementKey("mock_credential_one"), ElementKey("mock_credential_two")]

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                # Add authn data faking a reauthn event has taken place for this action
                sp_authn_req = SP_AuthnRequest(
                    post_authn_action=post_authn_action,
                    authn_instant=utc_now() - age,
                    frontend_action=frontend_action,
                    credentials_used=credentials_used,
                    finish_url=finish_url,
                )
                sess.authn.sp.authns[sp_authn_req.authn_id] = sp_authn_req

        return client

    # Authentication
    def test_no_authentication(self) -> None:
        # Unauthenticated request
        response = self.client.get("/")
        self.assertEqual(response.status_code, 401)

    def test_authentication_no_mfa(self) -> None:
        # Authenticated request
        assert isinstance(self.client, CSRFTestClient)
        with self.set_authn_action_custom(
            eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=False
        ) as client:
            with self.assertRaises(HTTPException) as http_error:
                response = client.get("/")
        self.assertEqual(http_error.exception.code, 403)

    def test_authentication_mfa(self) -> None:
        # Authenticated request with MFA
        assert isinstance(self.client, CSRFTestClient)
        with self.set_authn_action_custom(
            eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True
        ) as client:
            response = client.get("/")
        self.assertEqual(response.status_code, 200)  # Authenticated request

    # Search
    def test_search_existing_user(self) -> None:
        existing_mail_address = self.test_user.mail_addresses.to_list()[0]
        assert isinstance(self.client, CSRFTestClient)
        with self.set_authn_action_custom(
            eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True
        ) as client:
            response = client.post("/", data={"query": f"{existing_mail_address.email}"})
        assert b'<h3>1 user was found using query "johnsmith@example.com":</h3>' in response.data

    def test_search_non_existing_user(self) -> None:
        non_existing_mail_address = "not_in_db@example.com}"
        assert isinstance(self.client, CSRFTestClient)
        with self.set_authn_action_custom(
            eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True
        ) as client:
            response = client.post("/", data={"query": non_existing_mail_address})
        assert b"<h3>No users matched the search query</h3>" in response.data
