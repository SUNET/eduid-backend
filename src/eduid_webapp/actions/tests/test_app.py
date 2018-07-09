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
from werkzeug.exceptions import InternalServerError, Forbidden
from flask import Flask

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.actions.app import actions_init_app
from eduid_webapp.actions.action_abc import ActionPlugin


class TestingActionPlugin(ActionPlugin):

    def get_number_of_steps(self):
        return 1

    def get_url_for_bundle(self, action):
        if 'action_error' in action.to_dict()['params']:
            raise self.ActionError('test error')
        return "http://example.com/plugin.js"

    def get_config_for_bundle(self, action):
        if 'action_error' in action.to_dict()['params']:
            raise self.ActionError('test error')
        return {'setting1': 'dummy'}

    def perform_step(self, action):
        if 'action_error' in action.to_dict()['params']:
            raise self.ActionError('test error')
        if 'rm_action' in action.to_dict()['params']:
            raise self.ActionError('test error', rm=True)
        if 'validation_error' in action.to_dict()['params']:
            raise self.ValidationError({'field1': 'field test error'})
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
            'IDP_URL': 'https://example.com/idp',
            'PRESERVE_CONTEXT_ON_EXCEPTION': False
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

    def _prepare_session(self, sess, action_error=False, rm_action=False, validation_error=False,
                         total_steps=1, current_step=1, action=True, plugin=True):
        action_dict = deepcopy(DUMMY_ACTION)
        if action_error:
            action_dict['params']['action_error'] = True
        if rm_action:
            action_dict['params']['rm_action'] = True
        if validation_error:
            action_dict['params']['validation_error'] = True
        if action:
            self.app.actions_db.add_action(data=deepcopy(action_dict))
        action_dict['_id'] = str(action_dict['_id'])
        action_dict['user_oid'] = str(action_dict['user_oid'])
        sess['userid'] = str(action_dict['user_oid'])
        sess['current_action'] = action_dict
        sess['current_plugin'] = 'dummy'
        sess['idp_session'] = 'dummy-session'
        sess['current_step'] = current_step
        sess['total_steps'] = total_steps
        if plugin:
            self.app.plugins['dummy'] = TestingActionPlugin

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

    def test_authn_wrong_secret(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    eppn = 'dummy-eppn'
                    nonce = 'dummy-nonce-xxxx'
                    timestamp = str(hex(int(time.time())))
                    shared_key = 'wrong-shared-key'
                    token = sha256('{0}|{1}|{2}|{3}'.format(
                                   shared_key, eppn, nonce, timestamp)).hexdigest()
                url = '/?userid={}&token={}&nonce={}&ts={}'.format(eppn,
                                                                   token,
                                                                   nonce,
                                                                   timestamp)
                with self.app.test_request_context(url):
                    try:
                        response = client.get(url)
                    except Forbidden:
                        pass

    def test_get_config(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self._prepare_session(sess)
                    response = client.get('/config')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'], 'GET_ACTIONS_CONFIG_SUCCESS')
                    self.assertEquals(data['payload']['setting1'], 'dummy')

    def test_get_config_fails(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self._prepare_session(sess, action_error=True)
                    response = client.get('/config')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'], 'GET_ACTIONS_CONFIG_FAIL')
                    self.assertEquals(data['payload']['message'], 'test error')

    def test_get_actions(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self._prepare_session(sess)
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertTrue(data['action'])
                    self.assertEquals(data['url'], "http://example.com/plugin.js")

    def test_get_actions_action_error(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self._prepare_session(sess, action_error=True)
                with self.app.test_request_context('/get-actions'):
                    try:
                        response = client.get('/get-actions')
                    except InternalServerError:
                        pass

    def test_get_actions_no_action(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self._prepare_session(sess, action=False)
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertFalse(data['action'])
                    self.assertEquals(data['url'],
                            "https://example.com/idp?key=dummy-session")

    def test_get_actions_no_plugin(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self._prepare_session(sess, plugin=False)
                with self.app.test_request_context('/get-actions'):
                    try:
                        response = client.get('/get-actions')
                    except InternalServerError:
                        pass

    def test_post_action(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self._prepare_session(sess)
                with self.app.test_request_context():
                    response = client.post('/post-action')
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['data']['completed'], 'done')
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_SUCCESS')

    def test_post_action_action_error(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self._prepare_session(sess, action_error=True)
                with self.app.test_request_context():
                    response = client.post('/post-action')
                    data = json.loads(response.data)
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_FAIL')
                    self.assertEquals(data['payload']['message'], 'test error')

    def test_post_action_validation_error(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self._prepare_session(sess, validation_error=True)
                with self.app.test_request_context():
                    response = client.post('/post-action')
                    data = json.loads(response.data)
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_FAIL')
                    self.assertEquals(data['payload']['errors']['field1'], 'field test error')

    def test_post_action_multi_step(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self._prepare_session(sess, total_steps=2)
                with self.app.test_request_context():
                    response = client.post('/post-action')
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['data']['completed'], 'done')
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_SUCCESS')
                    response = client.post('/post-action')
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['data']['completed'], 'done')
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_SUCCESS')

    def test_post_action_rm_action(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self._prepare_session(sess, rm_action=True)
                with self.app.test_request_context():
                    response = client.post('/post-action')
                    data = json.loads(response.data)
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_FAIL')
                    self.assertEquals(data['payload']['message'], 'test error')
                    self.assertFalse(self.app.actions_db.has_actions(sess['userid']))
