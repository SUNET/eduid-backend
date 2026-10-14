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
