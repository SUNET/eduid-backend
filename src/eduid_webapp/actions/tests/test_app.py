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
from datetime import datetime
from typing import Optional

from werkzeug.exceptions import InternalServerError

from eduid_webapp.actions.testing import ActionsTestCase


class ActionsTests(ActionsTestCase):
    def update_actions_config(self, config):
        config['tou_version'] = 'test-version'
        return config

    # Parameterized test functions

    def _authn(self, timestamp: Optional[datetime] = None):
        """
        Set the (partial, not yet fully logged in) authn data in the session,
        and return the response to a GET request to the root of the service.

        :param timestamp: to control the timestamp set in the session at the beginning of authn'ing
        """
        eppn = self.test_eppn
        if timestamp is None:
            timestamp = datetime.fromtimestamp(int(time.time()))
        with self.session_cookie(self.browser) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    sess.common.eppn = eppn
                    sess.actions.ts = timestamp
                    sess.persist()
                    return client.get('/')

    def _get_config(self, **kwargs):
        """
        Prepare a mock actions session, and return the response to a request for client side configuration.

        The kwargs are passed directoly to the `prepare_session` method.
        """
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, **kwargs)
            return client.get('/config')

    def _get_actions(self, **kwargs):
        """
        Prepare a mock actions session, and return the response to a request for pending actions information.

        The kwargs are passed directoly to the `prepare_session` method.
        """
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, **kwargs)
            with self.app.test_request_context('/get-actions'):
                self.authenticate(idp_session='dummy-session')
                response = self.app.dispatch_request()
                return json.loads(response)

    def _post_action(self, csrf_token: Optional[str] = None, **kwargs):
        """
        Prepare a mock actions session, and return the response to a POST request with action data.

        The kwargs are passed directoly to the `prepare_session` method.

        :param csrf_token: what csrf token to include in the POST params.
        :param kwargs: params for the `prepare_session` method.
        """
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, **kwargs)
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    if csrf_token is None:
                        csrf_token = sess.get_csrf_token()
                    token = {'csrf_token': csrf_token}
            return client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)

    #  Actual tests

    def test_authn_no_data(self):
        response = self.browser.get('/')
        self.assertIn(b'Login action error', response.data)

    def test_authn(self):
        response = self._authn()
        self.assertIn(b'/get-actions', response.data)
        self.assertTrue(b'bundle-holder' in response.data)

    def test_authn_stale(self):
        timestamp = datetime.fromtimestamp(0)
        response = self._authn(timestamp=timestamp)
        self.assertIn(b'There was an error servicing your request', response.data)

    def test_get_config(self):
        response = self._get_config()
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data['payload']['setting1'], 'dummy')

    def test_get_config_fails(self):
        response = self._get_config(action_error=True)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data['payload']['message'], 'test error')

    def test_get_actions(self):
        data = self._get_actions()
        self.assertTrue(data['action'])
        self.assertEqual(data['url'], "http://example.com/plugin.js")

    def test_get_actions_action_error(self):
        with self.assertRaises(InternalServerError):
            self._get_actions(action_error=True)

    def test_get_actions_no_action(self):
        data = self._get_actions(add_action=False)
        self.assertFalse(data['action'])
        self.assertEqual(data['url'], 'https://example.com/idp?key=dummy-session')

    def test_get_actions_no_plugin(self):
        with self.assertRaises(InternalServerError):
            self._get_actions(set_plugin=False)

    def test_post_action(self):
        response = self._post_action()
        self._check_api_response(response, status=200, type_='POST_ACTIONS_POST_ACTION_SUCCESS')
        data = response.json
        self.assertEqual(data['payload']['data']['completed'], 'done')
        self.assertEqual(data['type'], 'POST_ACTIONS_POST_ACTION_SUCCESS')

    def test_post_action_no_csrf(self):
        response = self._post_action(csrf_token='')
        self._check_api_error(
            response, type_='POST_ACTIONS_POST_ACTION_FAIL', error={'csrf_token': ['CSRF failed to validate'],},
        )

    def test_post_action_wrong_csrf(self):
        response = self._post_action(csrf_token='wrong-token')
        self._check_api_error(
            response, type_='POST_ACTIONS_POST_ACTION_FAIL', error={'csrf_token': ['CSRF failed to validate'],},
        )

    def test_post_action_action_error(self):
        response = self._post_action(action_error=True)
        data = response.json
        self.assertEqual(data['type'], 'POST_ACTIONS_POST_ACTION_FAIL')
        self.assertEqual(data['payload']['message'], 'test error')

    def test_post_action_validation_error(self):
        response = self._post_action(validation_error=True)
        data = response.json
        self.assertEqual(data['type'], 'POST_ACTIONS_POST_ACTION_FAIL')
        self.assertEqual(data['payload']['errors']['field1'], 'field test error')

    def test_post_action_rm_action(self):
        response = self._post_action(rm_action=True)
        data = response.json
        self.assertEqual(data['type'], 'POST_ACTIONS_POST_ACTION_FAIL')
        self.assertEqual(data['payload']['message'], 'test error')

    def test_post_action_multi_step(self):
        with self.session_cookie(self.browser) as client:
            self.prepare_session(client, total_steps=2)
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    token = {'csrf_token': sess.get_csrf_token()}
            # First step
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEqual(data['payload']['data']['completed'], 'done')
            self.assertEqual(data['type'], 'POST_ACTIONS_POST_ACTION_SUCCESS')
            token = {'csrf_token': data['payload']['csrf_token']}
            # Second step
            response = client.post('/post-action', data=json.dumps(token), content_type=self.content_type_json)
            data = json.loads(response.data)
            self.assertEqual(data['payload']['data']['completed'], 'done')
            self.assertEqual(data['type'], 'POST_ACTIONS_POST_ACTION_SUCCESS')
