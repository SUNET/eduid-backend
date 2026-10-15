import pytest
from flask import Flask

from eduid.common.config.base import CaptchaConfigMixin, EduIDBaseAppConfig, MagicCookieMixin
from eduid.webapp.common.api.debug import _mask_uri_password, dump_config, log_endpoints


def test_log_endpoints_handles_routes_with_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    app = Flask("test")
    app.config["SERVER_NAME"] = "localhost"

    @app.route("/user/<name>")
    def user(name: str) -> str:
        return name

    # Flask also adds a static route, which has a 'filename' argument
    log_endpoints(app)

    output = capsys.readouterr().err
    assert "/user/[name]" in output
    assert "/static/[filename]" in output


def test_dump_config_includes_flask_config_and_app_conf(capsys: pytest.CaptureFixture[str]) -> None:
    app = Flask("test")
    app.config["SOME_FLASK_KEY"] = "flask-value"
    conf = EduIDBaseAppConfig(app_name="test_app", mongo_uri="mongodb://localhost/test")

    dump_config(app, conf)

    output = capsys.readouterr().err
    assert "('CONFIGURATION', 'app.config')" in output
    assert "('SOME_FLASK_KEY', 'flask-value')" in output
    assert "('CONFIGURATION', 'app.conf')" in output
    assert "('app_name', 'test_app')" in output


class DebugTestConfig(EduIDBaseAppConfig, MagicCookieMixin, CaptchaConfigMixin):
    ekopost_api_pw: str = ""


def test_dump_config_hides_credentials(capsys: pytest.CaptureFixture[str]) -> None:
    app = Flask("test")
    app.config["SECRET_KEY"] = "flask-secret-value"
    app.config["ORCID_CLIENT"] = {"client_id": "visible-client-id", "client_secret": "nested-secret-value"}
    app.config["PASSWORD_SERVICE_URL"] = "/services/reset-password/"
    app.config["EDUID_STATIC_URL"] = "https://static.example.org:8443/"
    conf = DebugTestConfig.model_validate(
        {
            "app_name": "test_app",
            "mongo_uri": "mongodb://dbuser:hunter2@localhost/test",
            "flask": {"secret_key": "conf-flask-secret"},
            "ekopost_api_pw": "ekopost-pw-value",
            "magic_cookie": "magic-cookie-value",
            "magic_cookie_name": "visible-cookie-name",
            "captcha_backdoor_code": "backdoor-value",
        }
    )

    dump_config(app, conf)

    output = capsys.readouterr().err
    secrets = (
        "flask-secret-value",
        "nested-secret-value",
        "hunter2",
        "conf-flask-secret",
        "ekopost-pw-value",
        "magic-cookie-value",
        "backdoor-value",
    )
    for secret in secrets:
        assert secret not in output
    # The keys are kept, only the values are masked
    assert "('SECRET_KEY', 'REDACTED')" in output
    assert "'client_secret': 'REDACTED'" in output
    assert "('ekopost_api_pw', 'REDACTED')" in output
    assert "('magic_cookie', 'REDACTED')" in output
    assert "('captcha_backdoor_code', 'REDACTED')" in output
    assert "mongodb://dbuser:REDACTED@localhost/test" in output
    # Values that are not credentials are still shown
    assert "visible-client-id" in output
    assert "('magic_cookie_name', 'visible-cookie-name')" in output
    assert "/services/reset-password/" in output
    assert "('EDUID_STATIC_URL', 'https://static.example.org:8443/')" in output


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("mongodb://dbuser:hunter2@localhost/test", "mongodb://dbuser:REDACTED@localhost/test"),
        ("redis://:hunter2@host:6379/0", "redis://:REDACTED@host:6379/0"),
        ("mongodb://u:hunter2@h1:27017,h2:27017/db?x=y", "mongodb://u:REDACTED@h1:27017,h2:27017/db?x=y"),
        ("mongodb://u:hun:ter2@h/db", "mongodb://u:REDACTED@h/db"),
        # nothing to mask
        ("mongodb://dbuser@localhost/test", "mongodb://dbuser@localhost/test"),
        ("https://example.org:8080/path", "https://example.org:8080/path"),
        ("http://h:80/a@b", "http://h:80/a@b"),
        ("not a uri: with a colon @ sign", "not a uri: with a colon @ sign"),
    ],
)
def test_mask_uri_password(uri: str, expected: str) -> None:
    assert _mask_uri_password(uri) == expected
