# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 NORDUnet A/S
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
from hashlib import sha256
from datetime import datetime
from nacl import secret, utils, encoding
from werkzeug.exceptions import InternalServerError, Forbidden

from eduid_webapp.actions.testing import ActionsTestCase


class ActionsTests(ActionsTestCase):

    def update_actions_config(self, config):
        config['TOU_VERSION'] = 'test-version'
        return config

    def test_authn_no_data(self):
        response = self.browser.get('/')
        self.assertIn(b'Login action error', response.data)

    def test_authn(self):
        eppn = self.test_eppn
        timestamp = datetime.fromtimestamp(int(time.time()))
        with self.app.test_client() as c:
            with c.session_transaction() as sess:
                sess.common.eppn = eppn
                sess.actions.ts = timestamp
                sess.persist()
            response = c.get('/')
            self.assertIn(b'/get-actions', response.data)
            self.assertTrue(b'bundle-holder' in response.data)

    def test_get_config(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client)
            response = client.get('/config')
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data.decode('utf-8'))
            self.assertEquals(data['payload']['setting1'], 'dummy')

    def test_get_config_fails(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, action_error=True)
            response = client.get('/config')
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data.decode('utf-8'))
            self.assertEquals(data['payload']['message'], 'test error')

    def test_get_actions(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client)
            response = client.get('/get-actions')
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertTrue(data['action'])
            self.assertEquals(data['url'], "http://example.com/plugin.js")

    def test_get_actions_action_error(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, action_error=True)
            with self.app.test_request_context('/get-actions'):
                try:
                    response = client.get('/get-actions')
                except InternalServerError:
                    pass

    def test_get_actions_no_action(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, add_action=False)
            with self.app.test_request_context('/get-actions'):
                self.authenticate(idp_session='dummy-session')
                response = self.app.dispatch_request()
                data = json.loads(response)
                self.assertFalse(data['action'])
                self.assertEquals(data['url'], 'https://example.com/idp?key=dummy-session')

    def test_get_actions_no_plugin(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, set_plugin=False)
            with self.app.test_request_context('/get-actions'):
                self.authenticate(idp_session='dummy-session')
                try:
                    self.app.dispatch_request()
                except InternalServerError:
                    pass

    def test_post_action_no_csrf(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client)
            with self.app.test_request_context():
                response = client.post('/post-action')
                data = json.loads(response.data)
                self.assertEquals(response.status_code, 400)
                self.assertEquals(data['message'], 'Bad Request')

    def test_post_action_wrong_csrf(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client)
            token = {'csrf_token': 'wrong code'}
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEquals(response.status_code, 400)
            self.assertEquals(data['message'], 'Bad Request')

    def test_post_action(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client)
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEquals(data['payload']['data']['completed'], 'done')
            self.assertEquals(data['type'], 'POST_ACTIONS_POST_ACTION_SUCCESS')

    def test_post_action_action_error(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, action_error=True)
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEquals(data['type'], 'POST_ACTIONS_POST_ACTION_FAIL')
            self.assertEquals(data['payload']['message'], 'test error')

    def test_post_action_validation_error(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, validation_error=True)
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEquals(data['type'], 'POST_ACTIONS_POST_ACTION_FAIL')
            self.assertEquals(data['payload']['errors']['field1'], 'field test error')

    def test_post_action_multi_step(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, total_steps=2)
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
            # First step
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEquals(data['payload']['data']['completed'], 'done')
            self.assertEquals(data['type'], 'POST_ACTIONS_POST_ACTION_SUCCESS')
            token = {'csrf_token': data['payload']['csrf_token']}
            # Second step
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEquals(data['payload']['data']['completed'], 'done')
            self.assertEquals(data['type'], 'POST_ACTIONS_POST_ACTION_SUCCESS')

    def test_post_action_rm_action(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, rm_action=True)
            with client.session_transaction() as sess:
                eppn = sess['eppn']
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEquals(data['type'], 'POST_ACTIONS_POST_ACTION_FAIL')
            self.assertEquals(data['payload']['message'], 'test error')
            self.assertFalse(self.app.actions_db.has_actions(eppn))
