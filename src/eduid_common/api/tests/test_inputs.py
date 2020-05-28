#  -*- encoding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import logging
from typing import Any, Dict
from urllib.parse import unquote

from flask import Blueprint, make_response, request
from marshmallow import ValidationError, fields
from werkzeug.http import dump_cookie

from eduid_userdb import UserDB

from eduid_common.api.app import EduIDBaseApp
from eduid_common.api.decorators import UnmarshalWith
from eduid_common.api.schemas.base import EduidSchema
from eduid_common.api.schemas.csrf import CSRFRequestMixin
from eduid_common.api.testing import EduidAPITestCase
from eduid_common.config.base import FlaskConfig
from eduid_common.session.eduid_session import SessionFactory

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


def dont_validate(value):
    raise ValidationError('Problem with {!r}'.format(value))


class NonValidatingSchema(EduidSchema, CSRFRequestMixin):
    test_data = fields.String(required=True, validate=dont_validate)

    class Meta:
        strict = True


test_views = Blueprint('test', __name__)


def _make_response(data):
    html = u'<html><body>{}</body></html>'.format(data)
    response = make_response(html, 200)
    response.headers['Content-Type'] = "text/html; charset=utf8"
    return response


@test_views.route('/test-get-param', methods=['GET'])
def get_param_view():
    param = request.args.get('test-param')
    return _make_response(param)


@test_views.route('/test-post-param', methods=['POST'])
def post_param_view():
    param = request.form.get('test-param')
    return _make_response(param)


@test_views.route('/test-post-json', methods=['POST'])
@UnmarshalWith(NonValidatingSchema)
def post_json_view(test_data):
    "never validates"
    pass


@test_views.route('/test-cookie')
def cookie_view():
    cookie = request.cookies.get('test-cookie')
    return _make_response(cookie)


@test_views.route('/test-empty-session')
def empty_session_view():
    cookie = request.cookies.get('sessid')
    return _make_response(cookie)


@test_views.route('/test-header')
def header_view():
    header = request.headers.get('X-TEST')
    return _make_response(header)


@test_views.route('/test-values', methods=['GET', 'POST'])
def values_view():
    param = request.values.get('test-param')
    return _make_response(param)


class InputsTestApp(EduIDBaseApp):
    def __init__(self, name: str, config: Dict[str, Any], **kwargs):
        self.config = FlaskConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)


class InputsTests(EduidAPITestCase):
    def update_config(self, config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        return config

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = InputsTestApp('testing', config)
        app.register_blueprint(test_views)
        app.central_userdb = UserDB(app.config.mongo_uri, 'eduid_am')
        app.session_interface = SessionFactory(app.config)
        return app

    def test_get_param(self):
        """"""
        url = '/test-get-param?test-param=test-param'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            self.assertIn(b'test-param', response.data)

    def test_get_param_script(self):
        """"""
        url = '/test-get-param?test-param=<script>alert("ho")</script>'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_get_param_script_percent_encoded(self):
        url = '/test-get-param?test-param=%3Cscript%3Ealert%28%22ho%22%29%3C%2Fscript%3E'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_get_param_script_percent_encoded_twice(self):
        url = '/test-get-param?test-param=%253Cscript%253Ealert%2528%2522ho%2522%2529%253C%252Fscript%253E'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            unquoted_response = unquote(response.data.decode('utf8'))
            self.assertNotIn(b'<script>', response.data)
            self.assertNotIn('<script>', unquoted_response)

    def test_get_param_unicode(self):
        url = '/test-get-param?test-param=åäöхэжこんにちわ'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            self.assertIn('åäöхэжこんにちわ', response.data.decode('utf8'))

    def test_get_param_unicode_percent_encoded(self):
        url = '/test-get-param?test-param=%C3%A5%C3%A4%C3%B6%D1%85%D1%8D%D0%B6%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%82%8F'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            self.assertIn('åäöхэжこんにちわ', response.data.decode('utf8'))

    def test_post_param_script(self):
        """"""
        url = '/test-post-param'
        with self.app.test_request_context(url, method='POST', data={'test-param': '<script>alert("ho")</script>'}):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_post_param_script_percent_encoded(self):
        url = '/test-post-param'
        with self.app.test_request_context(
            url, method='POST', data={'test-param': '%3Cscript%3Ealert%28%22ho%22%29%3C%2Fscript%3E'}
        ):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_post_param_script_percent_encoded_twice(self):
        url = '/test-post-param'
        with self.app.test_request_context(
            url, method='POST', data={'test-param': b'%253Cscript%253Ealert%2528%2522ho%2522%2529%253C%252Fscript%253E'}
        ):

            response = self.app.dispatch_request()
            unquoted_response = unquote(response.data.decode('ascii'))
            self.assertNotIn(b'<script>', response.data)
            self.assertNotIn('<script>', unquoted_response)

    def test_post_json_script(self):
        """"""
        url = '/test-post-json'
        with self.app.test_request_context(
            url,
            method='POST',
            content_type='application/json',
            headers={
                "X-Requested-With": "XMLHttpRequest",
                "Host": "test.localhost",
                "Origin": "http://test.localhost",
            },
            data='{"test_data": "<script>alert(42)</script>", "csrf_token": "failing-token"}',
        ):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_cookie_script(self):
        """"""
        url = '/test-cookie'
        cookie = dump_cookie('test-cookie', '<script>alert("ho")</script>')
        with self.app.test_request_context(url, method='GET', headers={'Cookie': cookie}):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_header_script(self):
        """"""
        url = '/test-header'
        script = '<script>alert("ho")</script>'
        with self.app.test_request_context(url, method='GET', headers={'X-TEST': script}):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_get_values_script(self):
        """"""
        url = '/test-values?test-param=test-param'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_post_values_script(self):
        """"""
        url = '/test-values'
        with self.app.test_request_context(url, method='POST', data={'test-param': '<script>alert("ho")</script>'}):

            response = self.app.dispatch_request()
            self.assertNotIn(b'<script>', response.data)

    def test_get_using_empty_session(self):
        """Test sending an empty sessid cookie"""
        url = '/test-empty-session'
        cookie = dump_cookie('sessid', '')
        with self.app.test_request_context(url, method='GET', headers={'Cookie': cookie}):

            # This is a regression test for the bug that would crash the
            # application before when someone sent an empty sessid cookie.
            # This state should be treated in the same way as no session
            # instead of crashing.
            response = self.app.dispatch_request()
            self.assertEqual(response.data, b'<html><body></body></html>')
