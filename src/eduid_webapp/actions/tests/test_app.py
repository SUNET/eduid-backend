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
import unittest
import six
from hashlib import sha256
import nacl.secret
import nacl.utils
from werkzeug.exceptions import InternalServerError, Forbidden

NEW_ACTIONS = True

try:
    from eduid_action.common.testing import ActionsTestCase
except ImportError:
    class ActionsTestCase: pass
    NEW_ACTIONS = False


class ActionsTests(ActionsTestCase):

    def update_actions_config(self, config):
        config['TOKEN_LOGIN_SHARED_KEY'] = config['TOKEN_LOGIN_SHARED_KEY'][:nacl.secret.SecretBox.KEY_SIZE]
        if len(config['TOKEN_LOGIN_SHARED_KEY']) < 32:
            config['TOKEN_LOGIN_SHARED_KEY'] += (32 - len(config['TOKEN_LOGIN_SHARED_KEY'])) * '0'
        if not isinstance(config['TOKEN_LOGIN_SHARED_KEY'], six.binary_type):
            config['TOKEN_LOGIN_SHARED_KEY'] = config['TOKEN_LOGIN_SHARED_KEY'].encode('ascii')
        self.assertEqual(32, len(config['TOKEN_LOGIN_SHARED_KEY']))
        return config

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_authn_no_data(self):
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 302)
        response = self.browser.get('/')
        self.assertEqual(response.status_code, 400)

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_authn(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    response = self.authenticate(client, sess)
                    self.assertEqual(response.status_code, 200)
                    self.assertTrue(b'bundle-holder' in response.data)

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_authn_hmac_and_userid(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    userid = '012345678901234567890123'
                    nonce = 'dummy-nonce-xxxx'
                    timestamp = str(hex(int(time.time())))
                    shared_key = self.app.config['TOKEN_LOGIN_SHARED_KEY']
                    token_data = '{0}|{1}|{2}|{3}'.format(shared_key, userid, nonce, timestamp)
                    hashed = sha256(token_data.encode('ascii'))
                    token = hashed.hexdigest()

                url = '/?userid={}&token={}&nonce={}&ts={}'.format(userid,
                                                                   token,
                                                                   nonce,
                                                                   timestamp)
                with self.app.test_request_context(url):
                    response = client.get(url)
                    self.assertEqual(response.status, '200 OK')

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_authn_hmac_and_eppn(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    eppn = 'dummy-eppn'
                    nonce = 'dummy-nonce-xxxx'
                    timestamp = str(hex(int(time.time())))
                    shared_key = self.app.config['TOKEN_LOGIN_SHARED_KEY']
                    token_data = '{0}|{1}|{2}|{3}'.format(shared_key, eppn, nonce, timestamp)
                    hashed = sha256(token_data.encode('ascii'))
                    token = hashed.hexdigest()

                url = '/?eppn={}&token={}&nonce={}&ts={}'.format(eppn,
                                                                 token,
                                                                 nonce,
                                                                 timestamp)
                with self.app.test_request_context(url):
                    response = client.get(url)
                    self.assertEqual(response.status, '200 OK')

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_authn_secret_box(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    eppn = b'dummy-eppn'
                    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
                    timestamp = str(hex(int(time.time())))
                    shared_key = self.app.config['TOKEN_LOGIN_SHARED_KEY']
                    token_data = b'{0}|{1}'.format(timestamp, eppn)
                    box = nacl.secret.SecretBox(shared_key)
                    encrypted = box.encrypt(token_data, nonce)
                    if six.PY2:
                        token = encrypted.encode('hex')
                        hex_nonce = nonce.encode('hex')
                    else:
                        token = encrypted.hex()
                        hex_nonce = nonce.hex()

                url = '/?userid={}&token={}&nonce={}&ts={}'.format(eppn,
                                                                   token,
                                                                   hex_nonce,
                                                                   timestamp)
                with self.app.test_request_context(url):
                    response = client.get(url)
                    self.assertEqual(response.status, '200 OK')

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_authn_wrong_secret(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    eppn = 'dummy-eppn'
                    nonce = 'dummy-nonce-xxxx'
                    timestamp = str(hex(int(time.time())))
                    shared_key = 'wrong-shared-key'
                    token_data = '{0}|{1}|{2}|{3}'.format(shared_key, eppn, nonce, timestamp)
                    hashed = sha256(token_data.encode('ascii'))
                    token = hashed.hexdigest()

                url = '/?userid={}&token={}&nonce={}&ts={}'.format(eppn,
                                                                   token,
                                                                   nonce,
                                                                   timestamp)
                with self.app.test_request_context(url):
                    with self.assertRaises(Forbidden):
                        response = client.get(url)

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_get_actions_action_error(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess, action_error=True)
                with self.app.test_request_context('/get-actions'):
                    try:
                        response = client.get('/get-actions')
                    except InternalServerError:
                        pass

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_get_actions_no_plugin(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess, set_plugin=False)
                with self.app.test_request_context('/get-actions'):
                    try:
                        response = client.get('/get-actions')
                    except InternalServerError:
                        pass

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
    def test_post_action_no_csrf(self):
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                self.prepare_session(sess)
                with self.app.test_request_context():
                    response = client.post('/post-action')
                    data = json.loads(response.data)
                    self.assertEquals(response.status_code, 400)
                    self.assertEquals(data['message'], 'Bad Request')

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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

    @unittest.skipUnless(NEW_ACTIONS, "Still using old actions")
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
