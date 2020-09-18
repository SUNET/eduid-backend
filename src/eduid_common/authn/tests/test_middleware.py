# -*- coding: utf-8 -*-
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

from contextlib import contextmanager
from typing import Any, Dict

from werkzeug.exceptions import NotFound

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.config.base import FlaskConfig


class AuthnTestApp(AuthnBaseApp):
    def __init__(self, name: str, config: Dict[str, Any], **kwargs):
        # This should be an AuthnConfig instance, but a FlaskConfig instance suffices for these
        # tests and we don't want eduid_common to depend on eduid_webapp.
        self.config = FlaskConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)


class AuthnTests(EduidAPITestCase):
    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return AuthnTestApp('testing', config)

    def update_config(self, config):
        config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'development': 'DEBUG',
                'application_root': '/',
                'no_authn_urls': [],
                'log_level': 'DEBUG',
                'am_broker_url': 'amqp://eduid:eduid_pw@rabbitmq/am',
                'msg_broker_url': 'amqp://eduid:eduid_pw@rabbitmq/msg',
                'celery_config': {
                    'result_backend': 'amqp',
                    'task_serializer': 'json',
                    'mongo_uri': config['mongo_uri'],
                },
            }
        )
        return config

    def test_get_view(self):
        response = self.browser.get('/some/path')
        self.assertEqual(response.status_code, 302)

        with self.session_cookie(self.browser, 'hubba-bubba') as client:
            with self.assertRaises(NotFound):
                client.get('/some/path')


class UnAuthnTests(EduidAPITestCase):
    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return AuthnTestApp('testing', config)

    def update_config(self, config):
        config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'development': 'DEBUG',
                'application_root': '/',
                'log_level': 'DEBUG',
                'am_broker_url': 'amqp://eduid:eduid_pw@rabbitmq/am',
                'msg_broker_url': 'amqp://eduid:eduid_pw@rabbitmq/msg',
                'celery_config': {
                    'result_backend': 'amqp',
                    'task_serializer': 'json',
                    'mongo_uri': config['mongo_uri'],
                },
            }
        )
        return config

    @contextmanager
    def session_cookie(self, client, server_name='localhost'):
        with client.session_transaction() as sess:
            sess.persist()
        client.set_cookie(server_name, key=self.app.config.session_cookie_name, value=sess._session.token.cookie_val)
        yield client

    def test_get_view(self):
        response = self.browser.get('/status/healthy')
        self.assertEqual(response.status_code, 200)
