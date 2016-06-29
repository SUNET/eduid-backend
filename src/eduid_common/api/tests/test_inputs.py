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

from werkzeug.http import dump_cookie
from flask import Flask, Blueprint
from flask import request
from flask import make_response

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.api.session import SessionFactory
from eduid_common.api.request import Request
from eduid_userdb import UserDB


import logging
logger = logging.getLogger(__name__)


test_views = Blueprint('test', __name__)


@test_views.route('/test-get-param', methods=['GET'])
def get_param_view():
    param = request.args.get('test-param')
    html = '<html><body>{}</body></html>'.format(param)
    response = make_response(html, 200)
    response.headers['Content-Type'] = "text/html; charset=utf8"
    return response


@test_views.route('/test-post-param', methods=['POST'])
def post_param_view():
    param = request.form.get('test-param')
    html = '<html><body>{}</body></html>'.format(param)
    response = make_response(html, 200)
    response.headers['Content-Type'] = "text/html; charset=utf8"
    return response


@test_views.route('/test-cookie')
def cookie_view():
    cookie = request.cookies.get('test-cookie')
    html = '<html><body>{}</body></html>'.format(cookie)
    response = make_response(html, 200)
    response.headers['Content-Type'] = "text/html; charset=utf8"
    return response


class InputsTests(EduidAPITestCase):

    def update_config(self, config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        config.update({
            })
        return config

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = Flask('test.localhost')
        app.request_class = Request
        app.config.update(config)
        app.register_blueprint(test_views)
        app.central_userdb = UserDB(app.config['MONGO_URI'], 'eduid_am')
        app.session_interface = SessionFactory(app.config)
        return app

    def test_get_param(self):
        """"""
        url = '/test-get-param?test-param=test-param'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            self.assertIn('test-param', response.data)

    def test_get_param_script(self):
        """"""
        url = '/test-get-param?test-param=<script>alert("ho")</script>'
        with self.app.test_request_context(url, method='GET'):

            response = self.app.dispatch_request()
            self.assertNotIn('<script>', response.data)

    def test_post_param_script(self):
        """"""
        url = '/test-post-param'
        with self.app.test_request_context(url, method='POST',
                data={'test-param': '<script>alert("ho")</script>'}):

            response = self.app.dispatch_request()
            self.assertNotIn('<script>', response.data)

    def test_post_param_script(self):
        """"""
        url = '/test-cookie'

        cookie = dump_cookie('test-cookie', '<script>alert("ho")</script>')
        with self.app.test_request_context(url, method='GET',
                                           headers={'Cookie': cookie}):

            response = self.app.dispatch_request()
            self.assertNotIn('<script>', response.data)
