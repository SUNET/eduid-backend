import pytest
from flask import Flask

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.webapp.common.api.debug import dump_config, log_endpoints


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


def test_dump_config_hides_credentials(capsys: pytest.CaptureFixture[str]) -> None:
    app = Flask("test")
    app.config["SECRET_KEY"] = "flask-secret-value"
    app.config["ORCID_CLIENT"] = {"client_id": "visible-client-id", "client_secret": "nested-secret-value"}
    app.config["PASSWORD_SERVICE_URL"] = "/services/reset-password/"
    app.config["EDUID_STATIC_URL"] = "https://static.example.org:8443/"
    conf = EduIDBaseAppConfig.model_validate(
        {
            "app_name": "test_app",
            "mongo_uri": "mongodb://dbuser:hunter2@localhost/test",
            "flask": {"secret_key": "conf-flask-secret"},
        }
    )

    dump_config(app, conf)

    output = capsys.readouterr().err
    for secret in ("flask-secret-value", "nested-secret-value", "hunter2", "conf-flask-secret"):
        assert secret not in output
    # The keys are kept, only the values are masked
    assert "('SECRET_KEY', 'REDACTED')" in output
    assert "'client_secret': 'REDACTED'" in output
    assert "mongodb://dbuser:REDACTED@localhost/test" in output
    # Values that are not credentials are still shown
    assert "visible-client-id" in output
    assert "/services/reset-password/" in output
    assert "https://static.example.org:8443/" in output
