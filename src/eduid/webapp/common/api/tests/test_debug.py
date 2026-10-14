import pytest
from flask import Flask

from eduid.webapp.common.api.debug import log_endpoints


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
