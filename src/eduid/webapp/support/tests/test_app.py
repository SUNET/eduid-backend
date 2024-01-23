from typing import Any, Mapping

from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.support.app import SupportApp, support_init_app

__author__ = "lundberg"


class SupportAppTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    app: SupportApp

    def setUp(self):
        super().setUp()

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
                "token_service_url_logout": "https://localhost/logout",
                "eduid_static_url": "https://testing.eduid.se/static/",
            }
        )
        return config

    def test_authenticate(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.client, self.test_user_eppn) as client:
            response = client.get("/")
        self.assertEqual(response.status_code, 200)  # Authenticated request

    def test_search_existing_user(self):
        existing_mail_address = self.test_user.mail_addresses.to_list()[0]
        with self.session_cookie(self.client, self.test_user_eppn) as client:
            response = client.post("/", data={"query": f"{existing_mail_address.email}"})
        assert b'<h3>1 user was found using query "johnsmith@example.com":</h3>' in response.data

    def test_search_non_existing_user(self):
        non_existing_mail_address = "not_in_db@example.com}"
        with self.session_cookie(self.client, self.test_user_eppn) as client:
            response = client.post("/", data={"query": non_existing_mail_address})
        assert b"<h3>No users matched the search query</h3>" in response.data
