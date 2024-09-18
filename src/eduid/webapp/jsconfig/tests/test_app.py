import json
import os
from collections.abc import Mapping
from pathlib import PurePath
from typing import Any, cast

from eduid.common.config.parsers import load_config
from eduid.common.testing_base import normalised_data
from eduid.webapp.common.api.testing import CSRFTestClient, EduidAPITestCase
from eduid.webapp.jsconfig.app import JSConfigApp, jsconfig_init_app
from eduid.webapp.jsconfig.settings.common import JSConfigConfig


class JSConfigTests(EduidAPITestCase[JSConfigApp]):
    def setUp(self):
        self.data_dir = str(PurePath(__file__).with_name("data"))
        super().setUp(copy_user_to_private=False)

    def load_app(self, config: Mapping[str, Any]) -> JSConfigApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = jsconfig_init_app(test_config=config)
        app.test_client_class = CSRFTestClient
        self.browser = cast(CSRFTestClient, app.test_client(allow_subdomain_redirects=True))
        app.url_map.host_matching = False
        return app

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "server_name": "example.com",
                "testing": True,
                "jsapps": {
                    "authn_service_url": "https://dashboard.example.com/services/authn",
                    "bankid_service_url": "https://dashboard.example.com/services/bankid",
                    "dashboard_link": "https://example.com/dashboard",
                    "eidas_service_url": "https://dashboard.example.com/services/eidas",
                    "emails_service_url": "https://dashboard.example.com/services/email",
                    "error_info_url": "https://idp.example.com/services/idp/error_info",
                    "faq_link": "https://example.com/faq",
                    "group_mgmt_service_url": "https://dashboard.example.com/services/group_mgmt",
                    "ladok_service_url": "https://dashboard.example.com/services/ladok",
                    "letter_proofing_service_url": "https://dashboard.example.com/services/letter",
                    "login_next_url": "https://idp.example.com/services/idp/next",
                    "login_request_other_url": "https://idp.example.com/services/idp/other",
                    "login_service_url": "https://idp.example.com/services/idp",
                    "lookup_mobile_proofing_service_url": "https://dashboard.example.com/services/mobile-proofing",
                    "orcid_service_url": "https://dashboard.example.com/services/orcid",
                    "password_entropy": 25,
                    "password_length": 12,
                    "personal_data_service_url": "https://dashboard.example.com/services/pdata",
                    "phone_service_url": "https://dashboard.example.com/services/phone",
                    "reset_password_link": "https://example.com/reset-password",
                    "reset_password_service_url": "https://idp.example.com/services/reset-password",
                    "security_service_url": "https://dashboard.example.com/services/security",
                    "signup_service_url": "https://signup.example.com/services/security",
                    "sentry_dsn": "sentry_dsn",
                    "signup_link": "https://example.com/signup",
                    "svipe_service_url": "https://dashboard.example.com/services/svipe",
                    "token_verify_idp": "https://some-other-idp.example.com",
                },
            }
        )
        return config

    def _validate_jsconfig(self, config_data: dict[str, Any]) -> None:
        assert config_data["type"] == "GET_JSCONFIG_CONFIG_SUCCESS"
        assert config_data["payload"].pop("success") is True  # success is added by _make_payload but probably shouldn't
        assert config_data["payload"]["csrf_token"] is not None

        config_data["payload"]["csrf_token"] = None  # csrf_token is None when config is first loaded
        assert normalised_data(self.app.conf.jsapps.dict()) == normalised_data(config_data["payload"])

    def test_get_config(self):
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            response = client.get("http://example.com/config")
            self.assertEqual(response.status_code, 200)
            self._validate_jsconfig(json.loads(response.data))

    def test_get_dashboard_config(self):
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn, subdomain="dashboard") as client:
            response = client.get("http://dashboard.example.com/dashboard/config")

            self.assertEqual(response.status_code, 200)
            self._validate_jsconfig(json.loads(response.data))

    def test_get_signup_config(self):
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn, subdomain="signup") as client:
            response = client.get("http://signup.example.com/signup/config")

            self.assertEqual(response.status_code, 200)
            self._validate_jsconfig(json.loads(response.data))

    def test_get_login_config(self):
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn, subdomain="login") as client:
            response = client.get("http://login.example.com/login/config")

            self.assertEqual(response.status_code, 200)
            self._validate_jsconfig(json.loads(response.data))

    def test_get_errors_config(self):
        eppn = self.test_user_data["eduPersonPrincipalName"]
        with self.session_cookie(self.browser, eppn) as client:
            response = client.get("http://example.com/errors/config")

            self.assertEqual(response.status_code, 200)
            self._validate_jsconfig(json.loads(response.data))

    def test_jsapps_config_from_yaml(self):
        os.environ["EDUID_CONFIG_YAML"] = f"{self.data_dir}/config.yaml"

        config = load_config(typ=JSConfigConfig, app_name="jsconfig", ns="webapp")
        assert self.app.conf.jsapps.dict() == config.jsapps.dict()
