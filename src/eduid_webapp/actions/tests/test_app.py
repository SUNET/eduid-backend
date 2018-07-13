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
from werkzeug.exceptions import InternalServerError, Forbidden

from eduid_webapp.actions.testing import ActionsTestCase


class ActionsTests(ActionsTestCase):

    def test_authn_no_data(self):
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 302)
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 400)

    def test_authn(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    response = self.authenticate(client, sess)
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
                    self.prepare_session(sess)
                    response = client.get('/config')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'], 'GET_ACTIONS_CONFIG_SUCCESS')
                    self.assertEquals(data['payload']['setting1'], 'dummy')

    def test_get_config_fails(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self.prepare_session(sess, action_error=True)
                    response = client.get('/config')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'], 'GET_ACTIONS_CONFIG_FAIL')
                    self.assertEquals(data['payload']['message'], 'test error')

    def test_get_actions(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self.prepare_session(sess)
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertTrue(data['action'])
                    self.assertEquals(data['url'], "http://example.com/plugin.js")

    def test_get_actions_action_error(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess, action_error=True)
                with self.app.test_request_context('/get-actions'):
                    try:
                        response = client.get('/get-actions')
                    except InternalServerError:
                        pass

    def test_get_actions_no_action(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    self.prepare_session(sess, add_action=False)
                    response = client.get('/get-actions')
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertFalse(data['action'])
                    self.assertEquals(data['url'],
                            "https://example.com/idp?key=dummy-session")

    def test_get_actions_no_plugin(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess, set_plugin=False)
                with self.app.test_request_context('/get-actions'):
                    try:
                        response = client.get('/get-actions')
                    except InternalServerError:
                        pass

    def test_post_action(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess)
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
                    response = client.post('/post-action',
                            data=json.dumps(token),
                            content_type=self.content_type_json)
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['data']['completed'], 'done')
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_SUCCESS')

    def test_post_action_no_csrf(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess)
                with self.app.test_request_context():
                    response = client.post('/post-action')
                    data = json.loads(response.data)
                    self.assertEquals(response.status_code, 400)
                    self.assertEquals(data['message'], 'Bad Request')

    def test_post_action_wrong_csrf(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess)
                with self.app.test_request_context():
                    token = {'csrf_token': 'wrong code'}
                    response = client.post('/post-action',
                            data=json.dumps(token),
                            content_type=self.content_type_json)
                    data = json.loads(response.data)
                    self.assertEquals(response.status_code, 400)
                    self.assertEquals(data['message'], 'Bad Request')

    def test_post_action_action_error(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess, action_error=True)
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
                    response = client.post('/post-action',
                            data=json.dumps(token),
                            content_type=self.content_type_json)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_FAIL')
                    self.assertEquals(data['payload']['message'], 'test error')

    def test_post_action_validation_error(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess, validation_error=True)
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
                    response = client.post('/post-action',
                            data=json.dumps(token),
                            content_type=self.content_type_json)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_FAIL')
                    self.assertEquals(data['payload']['errors']['field1'], 'field test error')

    def test_post_action_multi_step(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess, total_steps=2)
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
                    response = client.post('/post-action',
                            data=json.dumps(token),
                            content_type=self.content_type_json)
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['data']['completed'], 'done')
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_SUCCESS')
                    token = {'csrf_token': data['payload']['csrf_token']}
                    response = client.post('/post-action',
                            data=json.dumps(token),
                            content_type=self.content_type_json)
                    data = json.loads(response.data)
                    self.assertEquals(data['payload']['data']['completed'], 'done')
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_SUCCESS')

    def test_post_action_rm_action(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess, rm_action=True)
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
                    response = client.post('/post-action',
                            data=json.dumps(token),
                            content_type=self.content_type_json)
                    data = json.loads(response.data)
                    self.assertEquals(data['type'],
                            'POST_ACTIONS_POST_ACTION_FAIL')
                    self.assertEquals(data['payload']['message'], 'test error')
                    self.assertFalse(self.app.actions_db.has_actions(sess['userid']))
