from flask import Flask

from eduid.common.config.base import EduIDBaseAppConfig, Pysaml2SPConfigMixin
from eduid.webapp.common.api.utils import sanitise_redirect_url

__author__ = "lundberg"


class _StubConfig(EduIDBaseAppConfig, Pysaml2SPConfigMixin):
    pass


class TestSanitiseRedirectUrl:
    def setup_method(self) -> None:
        self.app = Flask(__name__)
        self.app.conf = _StubConfig(  # type: ignore[attr-defined]
            app_name="test", mongo_uri="mongodb://localhost/test", saml2_settings_module="dummy"
        )

    def test_none_returns_safe_default(self) -> None:
        with self.app.app_context():
            assert sanitise_redirect_url(None, safe_default="/safe") == "/safe"

    def test_plain_path_is_safe(self) -> None:
        with self.app.app_context():
            assert sanitise_redirect_url("/some/path") == "/some/path"

    def test_unrelated_domain_is_unsafe(self) -> None:
        with self.app.app_context():
            assert sanitise_redirect_url("http://evil.example.com/", safe_default="/safe") == "/safe"

    def test_backslash_open_redirect_is_rejected(self) -> None:
        """
        Regression test: browsers treat a leading backslash as a forward slash, so
        "/\\evil.com" is actually "//evil.com" (a protocol-relative open redirect) even
        though urlparse sees it as a harmless path-only URL.
        """
        with self.app.app_context():
            assert sanitise_redirect_url("/\\evil.com", safe_default="/safe") == "/safe"
            assert sanitise_redirect_url("\\\\evil.com", safe_default="/safe") == "/safe"
