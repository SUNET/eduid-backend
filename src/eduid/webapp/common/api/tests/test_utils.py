from flask import Flask

from eduid.common.config.base import EduIDBaseAppConfig, Pysaml2SPConfigMixin
from eduid.webapp.common.api.utils import make_short_code, sanitise_redirect_url

__author__ = "lundberg"


def test_make_short_code_default_length() -> None:
    for _ in range(100):
        code = make_short_code()
        assert len(code) == 6
        assert code.isdigit()


def test_make_short_code_honours_digits() -> None:
    for digits in (4, 6, 8, 10):
        code = make_short_code(digits=digits)
        assert len(code) == digits
        assert code.isdigit()


def test_make_short_code_uses_full_keyspace() -> None:
    """digits=8 must produce values above 1e6, not a 6-digit value zero-padded to 8."""
    codes = [make_short_code(digits=8) for _ in range(2000)]
    # The old implementation capped values at 1e6 and zero-padded, so no code ever exceeded 999999.
    assert any(int(code) >= 1_000_000 for code in codes), "keyspace still capped at 1e6"


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
