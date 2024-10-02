import logging
from collections.abc import Mapping
from typing import Any, NoReturn
from urllib.parse import unquote

from flask import Blueprint, Response, make_response, request
from marshmallow import ValidationError, fields
from werkzeug.http import dump_cookie

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.decorators import UnmarshalWith
from eduid.webapp.common.api.schemas.base import EduidSchema
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.session.eduid_session import SessionFactory

logger = logging.getLogger(__name__)

__author__ = "lundberg"


def dont_validate(value: Any) -> NoReturn:
    raise ValidationError(f"Problem with {value!r}")


class NonValidatingSchema(EduidSchema, CSRFRequestMixin):
    test_data = fields.String(required=True, validate=dont_validate)

    class Meta:
        strict = True


test_views = Blueprint("test", __name__)


def _make_response(data: str) -> Response:
    html = f"<html><body>{data}</body></html>"
    response = make_response(html, 200)
    response.headers["Content-Type"] = "text/html; charset=utf8"
    return response


@test_views.route("/test-get-param", methods=["GET"])
def get_param_view() -> Response:
    param = request.args.get("test-param")
    assert param
    return _make_response(param)


@test_views.route("/test-post-param", methods=["POST"])
def post_param_view() -> Response:
    param = request.form.get("test-param")
    assert param
    return _make_response(param)


@test_views.route("/test-post-json", methods=["POST"])  # type: ignore[arg-type]
@UnmarshalWith(NonValidatingSchema)
def post_json_view(test_data: str) -> None:
    """never validates"""
    pass


@test_views.route("/test-cookie")
def cookie_view() -> Response:
    cookie = request.cookies.get("test-cookie")
    assert cookie
    return _make_response(cookie)


@test_views.route("/test-empty-session")
def empty_session_view() -> Response:
    cookie = request.cookies.get("sessid")
    assert cookie is not None
    return _make_response(cookie)


@test_views.route("/test-header")
def header_view() -> Response:
    header = request.headers.get("X-TEST")
    assert header
    return _make_response(header)


@test_views.route("/test-values", methods=["GET", "POST"])
def values_view() -> Response:
    param = request.values.get("test-param")
    assert param
    return _make_response(param)


class InputsTestApp(EduIDBaseApp):
    def __init__(self, config: EduIDBaseAppConfig) -> None:
        super().__init__(config)

        self.conf = config

        self.session_interface = SessionFactory(config)


class InputsTests(EduidAPITestCase):
    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        return config

    def load_app(self, test_config: Mapping[str, Any]) -> InputsTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        config = load_config(typ=EduIDBaseAppConfig, app_name="testing", ns="webapp", test_config=test_config)
        app = InputsTestApp(config)
        app.register_blueprint(test_views)
        return app

    def test_get_param(self) -> None:
        """"""
        url = "/test-get-param?test-param=test-param"
        with self.app.test_request_context(url, method="GET"):
            response = self.app.dispatch_request()
            self.assertIn(b"test-param", response.data)

    def test_get_param_script(self) -> None:
        """"""
        url = '/test-get-param?test-param=<script>alert("ho")</script>'
        with self.app.test_request_context(url, method="GET"):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_get_param_script_percent_encoded(self) -> None:
        url = "/test-get-param?test-param=%3Cscript%3Ealert%28%22ho%22%29%3C%2Fscript%3E"
        with self.app.test_request_context(url, method="GET"):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_get_param_script_percent_encoded_twice(self) -> None:
        url = "/test-get-param?test-param=%253Cscript%253Ealert%2528%2522ho%2522%2529%253C%252Fscript%253E"
        with self.app.test_request_context(url, method="GET"):
            response = self.app.dispatch_request()
            unquoted_response = unquote(response.data.decode("utf8"))
            self.assertNotIn(b"<script>", response.data)
            self.assertNotIn("<script>", unquoted_response)

    def test_get_param_unicode(self) -> None:
        url = "/test-get-param?test-param=åäöхэжこんにちわ"
        with self.app.test_request_context(url, method="GET"):
            response = self.app.dispatch_request()
            self.assertIn("åäöхэжこんにちわ", response.data.decode("utf8"))

    def test_get_param_unicode_percent_encoded(self) -> None:
        url = (
            "/test-get-param?test-param="
            "%C3%A5%C3%A4%C3%B6%D1%85%D1%8D%D0%B6%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%82%8F"
        )
        with self.app.test_request_context(url, method="GET"):
            response = self.app.dispatch_request()
            self.assertIn("åäöхэжこんにちわ", response.data.decode("utf8"))

    def test_post_param_script(self) -> None:
        """"""
        url = "/test-post-param"
        with self.app.test_request_context(url, method="POST", data={"test-param": '<script>alert("ho")</script>'}):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_post_param_script_percent_encoded(self) -> None:
        url = "/test-post-param"
        with self.app.test_request_context(
            url, method="POST", data={"test-param": "%3Cscript%3Ealert%28%22ho%22%29%3C%2Fscript%3E"}
        ):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_post_param_script_percent_encoded_twice(self) -> None:
        url = "/test-post-param"
        with self.app.test_request_context(
            url, method="POST", data={"test-param": b"%253Cscript%253Ealert%2528%2522ho%2522%2529%253C%252Fscript%253E"}
        ):
            response = self.app.dispatch_request()
            unquoted_response = unquote(response.data.decode("ascii"))
            self.assertNotIn(b"<script>", response.data)
            self.assertNotIn("<script>", unquoted_response)

    def test_post_json_script(self) -> None:
        """"""
        url = "/test-post-json"
        with self.app.test_request_context(
            url,
            method="POST",
            content_type="application/json",
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Host": "test.localhost",
                "Origin": "http://test.localhost",
            },
            data='{"test_data": "<script>alert(42)</script>", "csrf_token": "failing-token"}',
        ):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_cookie_script(self) -> None:
        """"""
        url = "/test-cookie"
        cookie = dump_cookie("test-cookie", '<script>alert("ho")</script>')
        with self.app.test_request_context(url, method="GET", headers={"Cookie": cookie}):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_header_script(self) -> None:
        """"""
        url = "/test-header"
        script = '<script>alert("ho")</script>'
        with self.app.test_request_context(url, method="GET", headers={"X-TEST": script}):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_get_values_script(self) -> None:
        """"""
        url = "/test-values?test-param=test-param"
        with self.app.test_request_context(url, method="GET"):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_post_values_script(self) -> None:
        """"""
        url = "/test-values"
        with self.app.test_request_context(url, method="POST", data={"test-param": '<script>alert("ho")</script>'}):
            response = self.app.dispatch_request()
            self.assertNotIn(b"<script>", response.data)

    def test_get_using_empty_session(self) -> None:
        """Test sending an empty sessid cookie"""
        url = "/test-empty-session"
        cookie = dump_cookie("sessid", "")
        with self.app.test_request_context(url, method="GET", headers={"Cookie": cookie}):
            # This is a regression test for the bug that would crash the
            # application before when someone sent an empty sessid cookie.
            # This state should be treated in the same way as no session
            # instead of crashing.
            response = self.app.dispatch_request()
            self.assertEqual(response.data, b"<html><body></body></html>")
