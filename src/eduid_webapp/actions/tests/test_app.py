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
from copy import deepcopy
from contextlib import contextmanager
from hashlib import sha256
from bson import ObjectId
from mock import patch
from flask import Flask

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.actions.app import actions_init_app
from eduid_webapp.actions.action_abc import ActionPlugin


class TestingActionPlugin(ActionPlugin):

    def get_number_of_steps(self):
        return 1

    def get_url_for_bundle(self, action):
        return "http://example.com/plugin.js"

    def get_config_for_bundle(self, action):
        if 'raise' in action.to_dict()['params']:
            raise self.ActionError('test error')
        return {'setting1': 'dummy'}

    def perform_step(action):
        return {'completed': 'done'}


DUMMY_ACTION = {
    '_id': ObjectId('234567890123456789012301'),
    'user_oid': ObjectId('123467890123456789014567'),
    'action': 'dummy',
    'preference': 100, 
    'params': {
    }
}


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
        self.assertEqual(response.status_code, 400)

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
                url = '/?userid={}&token={}&nonce={}&ts={}'.format(eppn,
                                                                   token,
                                                                   nonce,
                                                                   timestamp)
                response = client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertTrue('bundle-holder' in response.data)

    def test_get_config(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self.app.actions_db.add_action(data=DUMMY_ACTION)
                    self.app.plugins['dummy'] = TestingActionPlugin
                    sess['current_plugin'] = 'dummy'
                    action_dict = deepcopy(DUMMY_ACTION)
                    action_dict['_id'] = str(action_dict['_id'])
                    action_dict['user_oid'] = str(action_dict['user_oid'])
                    sess['current_action'] = action_dict
                    response = client.get('/config')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'], 'GET_ACTIONS_CONFIG_SUCCESS')
                    self.assertEquals(data['payload']['setting1'], 'dummy')

    def test_get_config_fails(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self.app.plugins['dummy'] = TestingActionPlugin
                    sess['current_plugin'] = 'dummy'
                    action_dict = deepcopy(DUMMY_ACTION)
                    action_dict['params']['raise'] = True
                    self.app.actions_db.add_action(data=deepcopy(action_dict))
                    action_dict['_id'] = str(action_dict['_id'])
                    action_dict['user_oid'] = str(action_dict['user_oid'])
                    sess['current_action'] = action_dict
                    response = client.get('/config')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'], 'GET_ACTIONS_CONFIG_FAIL')
                    self.assertEquals(data['payload']['message'], 'test error')

    def test_get_actions(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self.app.actions_db.add_action(data=DUMMY_ACTION)
                    self.app.plugins['dummy'] = TestingActionPlugin
                    sess['current_plugin'] = 'dummy'
                    action_dict = deepcopy(DUMMY_ACTION)
                    action_dict['_id'] = str(action_dict['_id'])
                    action_dict['user_oid'] = str(action_dict['user_oid'])
                    sess['userid'] = str(action_dict['user_oid'])
                    sess['current_action'] = action_dict
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertTrue(data['action'])
                    self.assertEquals(data['url'], "http://example.com/plugin.js")
