from collections.abc import Mapping
from typing import Any, cast

import flask
from flask.wrappers import Response as FlaskResponse

from eduid.common.config.base import EduIDBaseAppConfig
from eduid.common.config.parsers import load_config
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.decorators import MarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.api.tests.test_messages import TestsMsg
from eduid.webapp.common.session.eduid_session import SessionFactory


class DecoratorTestConfig(EduIDBaseAppConfig):
    pass


class DecoratorTestApp(EduIDBaseApp):
    def __init__(self, config: DecoratorTestConfig):
        super().__init__(config)

        self.conf = config


test_views = flask.Blueprint("test", __name__, url_prefix="/test")


@test_views.route("/foo", methods=["GET"])
@MarshalWith(FluxStandardAction)
def flask_view(ret: FluxData) -> FluxData:
    """Fake flask view, returning a FluxData that will be turned into a FluxResponse by the decorator."""
    return ret


class MarshalDecoratorTests(EduidAPITestCase):
    # def setUp(self) -> None:
    #     self.app = EduIDBaseApp(__name__)
    #     self.app.register_blueprint(test_views)

    app: DecoratorTestApp

    def load_app(self, config: Mapping[str, Any]) -> DecoratorTestApp:
        """
        Called from the parent class, so we can provide the appropriate flask app for this test case.
        """
        _config = load_config(typ=DecoratorTestConfig, app_name="testing", ns="webapp", test_config=config)
        app = DecoratorTestApp(_config)
        app.register_blueprint(test_views)
        app.session_interface = SessionFactory(app.conf)
        return app

    def test_success_message(self):
        """Test that a simple success_message is turned into a well-formed Flux Standard Action response"""
        msg = success_response(message=TestsMsg.fst_test_msg)
        with self.app.test_request_context("/test/foo"):
            response = flask_view(msg)
            assert response.json == {
                "type": "GET_TEST_TEST_FOO_SUCCESS",
                "payload": {"message": "test.first_msg", "success": True},
            }

    def test_success_message_with_data(self):
        """Test that a success_message with data is turned into a well-formed Flux Standard Action response"""
        msg = success_response(payload={"working": True}, message=TestsMsg.fst_test_msg)
        with self.app.test_request_context("/test/foo"):
            response = flask_view(msg)
            assert response.json == {
                "type": "GET_TEST_TEST_FOO_SUCCESS",
                "payload": {"message": "test.first_msg", "success": True, "working": True},
            }

    def test_error_message(self):
        """Test that a simple success_message is turned into a well-formed Flux Standard Action response"""
        msg = error_response(message=TestsMsg.fst_test_msg)
        with self.app.test_request_context("/test/foo"):
            response = flask_view(msg)
            assert response.json == {
                "type": "GET_TEST_TEST_FOO_FAIL",
                "error": True,
                "payload": {"message": "test.first_msg", "success": False},
            }

    def test_error_message_with_data(self) -> None:
        """Test that an error_message with data is turned into a well-formed Flux Standard Action response"""
        msg = error_response(payload={"working": True}, message=TestsMsg.fst_test_msg)
        with self.app.test_request_context("/test/foo"):
            response = cast(FlaskResponse, flask_view(msg))
            assert response.get_json() == {
                "type": "GET_TEST_TEST_FOO_FAIL",
                "error": True,
                "payload": {"message": "test.first_msg", "success": False, "working": True},
            }
