from unittest.case import TestCase

import flask

from eduid.webapp.common.api.decorators import MarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.base import FluxStandardAction
from eduid.webapp.common.api.tests.test_messages import TestsMsg

test_views = flask.Blueprint('test', __name__, url_prefix='/test', template_folder='templates')


class MarshalDecoratorTests(TestCase):
    def setUp(self) -> None:
        self.app = flask.Flask(__name__)
        self.app.register_blueprint(test_views)

    @MarshalWith(FluxStandardAction)
    @test_views.route('/foo', methods=['GET'])
    def flask_view(self, ret: FluxData):
        """ Fake flask view, returning a FluxData that will be turned into a FluxResponse by the decorator. """
        return ret

    def test_success_message(self):
        """ Test that a simple success_message is turned into a well-formed Flux Standard Action response"""
        msg = success_response(message=TestsMsg.fst_test_msg)
        with self.app.test_request_context('/test/foo'):
            response = self.flask_view(msg)
            assert response.json == {
                'type': 'GET_TEST_TEST_FOO_SUCCESS',
                'payload': {'message': 'test.first_msg', 'success': True},
            }

    def test_success_message_with_data(self):
        """ Test that a success_message with data is turned into a well-formed Flux Standard Action response"""
        msg = success_response(payload={'working': True}, message=TestsMsg.fst_test_msg)
        with self.app.test_request_context('/test/foo'):
            response = self.flask_view(msg)
            assert response.json == {
                'type': 'GET_TEST_TEST_FOO_SUCCESS',
                'payload': {'message': 'test.first_msg', 'success': True, 'working': True},
            }

    def test_error_message(self):
        """ Test that a simple success_message is turned into a well-formed Flux Standard Action response"""
        msg = error_response(message=TestsMsg.fst_test_msg)
        with self.app.test_request_context('/test/foo'):
            response = self.flask_view(msg)
            assert response.json == {
                'type': 'GET_TEST_TEST_FOO_FAIL',
                'error': True,
                'payload': {'message': 'test.first_msg', 'success': False},
            }

    def test_error_message_with_data(self):
        """ Test that an error_message with data is turned into a well-formed Flux Standard Action response"""
        msg = error_response(payload={'working': True}, message=TestsMsg.fst_test_msg)
        with self.app.test_request_context('/test/foo'):
            response = self.flask_view(msg)
            assert response.json == {
                'type': 'GET_TEST_TEST_FOO_FAIL',
                'error': True,
                'payload': {'message': 'test.first_msg', 'success': False, 'working': True},
            }
