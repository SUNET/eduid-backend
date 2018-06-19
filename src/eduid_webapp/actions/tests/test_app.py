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

import json
import time
from contextlib import contextmanager
from hashlib import sha256
from mock import patch
from flask import Flask

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.actions.app import actions_init_app


class ActionsTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropiate flask
        app for this test case.
        """
        return actions_init_app('actions', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English','sv': 'Svenska'},
            'DASHBOARD_URL': '/profile/',
            'DEVELOPMENT': 'DEBUG',
            'APPLICATION_ROOT': '/',
            'LOG_LEVEL': 'DEBUG',
            'AM_BROKER_URL': 'amqp://eduid:eduid_pw@rabbitmq/am',
            'MSG_BROKER_URL': 'amqp://eduid:eduid_pw@rabbitmq/msg',
            'TOKEN_LOGIN_SHARED_KEY': 'shared_secret_Eifool0ua0eiph7ooch0',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json',
                'MONGO_URI': config['MONGO_URI'],
            },
        })
        return config

    def tearDown(self):
        super(ActionsTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()
            self.app.actions_db._drop_whole_collection()

    @contextmanager
    def session_cookie(self, client, server_name='localhost'):
        with client.session_transaction() as sess:
            sess.persist()
        client.set_cookie(server_name, key=self.app.config.get('SESSION_COOKIE_NAME'), value=sess._session.token)
        yield client

    def test_authn_no_data(self):
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 302)
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertTrue(data['error'])
        self.assertEquals(data['type'], 'GET_ACTIONS_FAIL')
        self.assertEquals(data['payload']['error']['idp_session'],
                                    [u'Missing data for required field.'])
        self.assertEquals(data['payload']['error']['nonce'],
                                    [u'Missing data for required field.'])
        self.assertEquals(data['payload']['error']['timestamp'],
                                    [u'Missing data for required field.'])
        self.assertEquals(data['payload']['error']['token'],
                                    [u'Missing data for required field.'])
        self.assertEquals(data['payload']['error']['userid'],
                                    [u'Missing data for required field.'])

    def test_authn(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    eppn = 'dummy-eppn'
                    nonce = 'dummy-nonce-xxxx'
                    timestamp = str(hex(int(time.time())))
                    shared_key = self.app.config.get('TOKEN_LOGIN_SHARED_KEY')
                    token = sha256('{0}|{1}|{2}|{3}'.format(
                                   shared_key, eppn, nonce, timestamp)).hexdigest()
                    data = {
                        'idp_session': 'dummy-session',
                        'userid': eppn,
                        'nonce': nonce,
                        'timestamp': timestamp,
                        'token': token,
                        'csrf_token': sess.get_csrf_token()
                    }
                response = client.get('/', data=json.dumps(data),
                                       content_type=self.content_type_json)
                self.assertEqual(response.status_code, 200)
                data = json.loads(response.data)
                self.assertEquals(data['type'], 'GET_ACTIONS_SUCCESS')
