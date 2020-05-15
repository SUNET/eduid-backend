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
from urllib.parse import unquote

from flask import Blueprint, request, current_app, abort
from marshmallow import ValidationError, fields
from werkzeug.http import dump_cookie

from eduid_userdb import UserDB

from eduid_common.api.app import EduIDBaseApp
from eduid_common.api.decorators import UnmarshalWith
from eduid_common.api.helpers import check_magic_cookie
from eduid_common.api.schemas.csrf import CSRFRequestMixin
from eduid_common.api.testing import EduidAPITestCase
from eduid_common.config.base import FlaskConfig
from eduid_common.session.eduid_session import SessionFactory


test_views = Blueprint('test', __name__)


@test_views.route('/get-code', methods=['GET'])
def get_code():
    try:
        if check_magic_cookie(current_app.config):
            eppn = request.args.get('eppn')
            return f"dummy-code-for-{eppn}"
    except Exception:
        pass

    abort(400)


class BackdoorTests(EduidAPITestCase):
    def update_config(self, config):
        """
        Called from the parent class, so that we can update the configuration
        according to the needs of this test case.
        """
        config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'no_authn_urls': [r'/get-code'],
                'environment': 'dev',
                'magic_cookie_name': 'magic-cookie',
                'magic_cookie': 'magic-cookie',
            }
        )
        return config

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = EduIDBaseApp('testing', FlaskConfig, config)
        app.register_blueprint(test_views)
        app.session_interface = SessionFactory(app.config)
        return app

    def test_backdoor_get_code(self):
        """"""
        with self.session_cookie_anon(self.browser) as client:

            client.set_cookie('localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie)
            response = client.get('/get-code?eppn=pepin-pepon')
            self.assertEqual(response.data, b'dummy-code-for-pepin-pepon')

    def test_no_backdoor_in_pro(self):
        """"""
        self.app.config.environment = 'pro'

        with self.session_cookie_anon(self.browser) as client:

            client.set_cookie('localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie)
            response = client.get('/get-code?eppn=pepin-pepon')
            self.assertEqual(response.status_code, 400)

    def test_no_backdoor_in_without_cookie(self):
        """"""
        with self.session_cookie_anon(self.browser) as client:

            response = client.get('/get-code?eppn=pepin-pepon')
            self.assertEqual(response.status_code, 400)

    def test_no_magic_cookie_no_backdoor(self):
        """"""
        self.app.config.magic_cookie = ''

        with self.session_cookie_anon(self.browser) as client:

            client.set_cookie('localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie)
            response = client.get('/get-code?eppn=pepin-pepon')
            self.assertEqual(response.status_code, 400)

    def test_no_magic_cookie_name_no_backdoor(self):
        """"""
        self.app.config.magic_cookie_name = ''

        with self.session_cookie_anon(self.browser) as client:

            client.set_cookie('localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie)
            response = client.get('/get-code?eppn=pepin-pepon')
            self.assertEqual(response.status_code, 400)
