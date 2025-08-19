from collections.abc import Mapping
from typing import Any

from eduid.common.config.base import FrontendAction
from eduid.userdb.testing import SetupConfig
from eduid.webapp.common.api.testing import EduidAPITestCase
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
                "authn_service_url_login": "https://localhost/login",
                "authn_service_url_logout": "https://localhost/logout",
                "eduid_static_url": "https://testing.eduid.se/static/",
            }
        )
        return config

    # Authentication
    def test_no_authentication(self) -> None:
        # Unauthenticated request
        response = self.browser.get("/search-form")
        self.assertEqual(response.status_code, 401)

    def test_authentication_no_mfa(self) -> None:
        # Authenticated request
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=False)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            resp = client.get("/search-form")
            assert resp.status_code == 302
            assert resp.headers.get("Location") == self.app.conf.authn_service_url_login

    def test_authentication_mfa(self) -> None:
        # Authenticated request with MFA
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.get("/search-form")
        self.assertEqual(response.status_code, 200)  # Authenticated request

    # Search
    def test_search_existing_user(self) -> None:
        existing_mail_address = self.test_user.mail_addresses.to_list()[0]
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.post("/search", data={"query": f"{existing_mail_address.email}"})
        assert b'<h3>1 user was found using query "johnsmith@example.com":</h3>' in response.data

    def test_search_non_existing_user(self) -> None:
        non_existing_mail_address = "not_in_db@example.com"
        self.set_authn_action(eppn=self.test_user_eppn, frontend_action=FrontendAction.LOGIN, mock_mfa=True)
        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            response = client.post("/search", data={"query": non_existing_mail_address})
        assert b"<h3>No users matched the search query: not_in_db@example.com</h3>" in response.data
