from collections.abc import Mapping
from typing import Any

from werkzeug.exceptions import NotFound

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.middleware import AuthnBaseApp


class AuthnTestApp(AuthnBaseApp):
    def __init__(self, name: str, test_config: Mapping[str, Any], **kwargs: Any):
        # This should be an AuthnConfig instance, but an EduIDBaseAppConfig instance suffices for these
        # tests and we don't want eduid.webapp.common to depend on eduid.webapp.
        self.conf = load_config(typ=EduIDBaseAppConfig, app_name=name, ns="webapp", test_config=test_config)
        super().__init__(self.conf, **kwargs)


class AuthnTests(EduidAPITestCase):
    def load_app(self, config: dict[str, Any]) -> AuthnTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return AuthnTestApp("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "development": "DEBUG",
                "application_root": "/",
                "no_authn_urls": [],
                "log_level": "DEBUG",
            }
        )
        return config

    def test_get_view(self) -> None:
        response = self.browser.get("/some/path")
        self.assertEqual(response.status_code, 401)

        with self.session_cookie(self.browser, "hubba-bubba") as client:
            with self.assertRaises(NotFound):
                client.get("/some/path")


class UnAuthnTests(EduidAPITestCase):
    def load_app(self, config: dict[str, Any]) -> AuthnTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return AuthnTestApp("testing", config)

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        config.update(
            {
                "available_languages": {"en": "English", "sv": "Svenska"},
                "development": "DEBUG",
                "application_root": "/",
                "log_level": "DEBUG",
            }
        )
        return config

    def test_get_view(self) -> None:
        response = self.browser.get("/status/healthy")
        self.assertEqual(response.status_code, 200)
