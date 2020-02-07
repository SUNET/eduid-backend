# -*- coding: utf8 -*-#

# Copyright (c) 2017 NORDUnet A/S
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
from __future__ import absolute_import

import json
import base64
from bson import ObjectId
from mock import patch
from eduid_common.session import session
from eduid_userdb.credentials import U2F
from eduid_userdb.testing import MOCKED_USER_STANDARD
from eduid_webapp.actions.testing import MockIdPContext
from eduid_webapp.actions.testing import ActionsTestCase
from eduid_webapp.actions.actions.mfa import Plugin
from eduid_userdb.exceptions import UserDoesNotExist

from fido2.server import Fido2Server

__author__ = 'ft'

MFA_ACTION = {
        '_id': ObjectId('234567890123456789012301'),
        'eppn': MOCKED_USER_STANDARD['eduPersonPrincipalName'],
        'action': 'mfa',
        'session': 'mock-session',
        'preference': 1,
        'params': {}
        }


def add_actions(context, user, ticket):
    """
    This is a stripped down version of eduid_idp.mfa_action.add_actions
    that adds the action unconditionally.
    """
    action = context.actions_db.add_action(
        user.eppn,
        action_type = 'mfa',
        preference = 1,
        session = ticket.key,
        params = {})
    session['current_plugin'] = 'mfa'
    action_d = action.to_dict()
    action_d['_id'] = str(action_d['_id'])
    session['current_action'] = action_d
    session.persist()

class MockTicket:
    def __init__(self, key):
        self.key = key
        self.mfa_action_creds = {}


class MFAActionPluginTests(ActionsTestCase):

    def setUp(self):
        super(MFAActionPluginTests, self).setUp()
        u2f = U2F(version='U2F_V2',
                  app_id='https://dev.eduid.se/u2f-app-id.json',
                  keyhandle='test_key_handle',
                  public_key='test_public_key',
                  attest_cert='test_attest_cert',
                  description='test_description',
                  )
        self.user.credentials.add(u2f)
        self.app.central_userdb.save(self.user, check_sync=False)

    def update_actions_config(self, config):
        config['action_plugins'] = ['mfa']
        config['mfa_testing'] = False
        config['u2f_app_id'] = 'https://example.com'
        config['u2f_valid_facets'] = [
            'https://dashboard.dev.eduid.se',
            'https://idp.dev.eduid.se']
        config['fido2_rp_id'] = 'idp.example.com'
        config['eidas_url'] = 'https://eidas.dev.eduid.se/mfa-authentication'
        config['mfa_authn_idp'] = 'https://eidas-idp.example.com'
        return config

    def test_get_mfa_action(self):
        mock_idp_app = MockIdPContext(self.app.actions_db)
        with self.app.test_request_context('/get-actions'):
            add_actions(mock_idp_app, self.user, MockTicket('mock-session'))
            self.authenticate(idp_session='mock-session')
            response = self.app.dispatch_request()
            data = json.loads(response)
            self.assertEqual(data['action'], True)
            self.assertEqual(data['url'], 'http://example.com/bundles/eduid_action.mfa-bundle.dev.js')
            self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_get_mfa_action_wrong_session(self):
        mock_idp_app = MockIdPContext(self.app.actions_db)
        with self.app.test_request_context('/get-actions'):
            mock_idp_app = MockIdPContext(self.app.actions_db)
            add_actions(mock_idp_app, self.user,
                    MockTicket('mock-session'))
            self.authenticate(idp_session='wrong-session')
            response = self.app.dispatch_request()
            data = json.loads(response)
            self.assertEqual(data['action'], False)
            self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_get_config(self):
        mock_idp_app = MockIdPContext(self.app.actions_db)
        with self.app.test_request_context('/config'):
            self.app.config.generate_u2f_challenges = True
            mock_idp_app = MockIdPContext(self.app.actions_db)
            add_actions(mock_idp_app, self.user, MockTicket('mock-session'))
            self.authenticate(idp_session='mock-session')
            response = self.app.dispatch_request()
            data = json.loads(response.data)
            u2f_data = json.loads(data['payload']['u2fdata'])
            self.assertEqual(u2f_data["registeredKeys"][0]["keyHandle"], "test_key_handle")
            self.assertEqual(u2f_data["registeredKeys"][0]["version"], "U2F_V2")
            self.assertEqual(u2f_data["appId"], "https://example.com")
            self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_get_config_no_user(self):
        self.app.central_userdb.remove_user_by_id(self.user.user_id)
        mock_idp_app = MockIdPContext(self.app.actions_db)
        with self.app.test_request_context('/get-actions'):
            mock_idp_app = MockIdPContext(self.app.actions_db)
            add_actions(mock_idp_app, self.user, MockTicket('mock-session'))
            self.authenticate(idp_session='mock-session')
            with self.assertRaises(UserDoesNotExist):
                self.app.dispatch_request()

    def test_action_no_token_response(self):
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'mfa', action_dict=MFA_ACTION)
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    csrf_token = sess.get_csrf_token()
                    data = json.dumps({'csrf_token': csrf_token})
                    response = client.post('/post-action', data=data, content_type=self.content_type_json)
                    data = json.loads(response.data.decode('utf-8'))
                    self.assertEqual(data['payload']['message'], "mfa.no-token-response")
                    self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    @patch('eduid_common.authn.fido_tokens.complete_authentication')
    def test_action_wrong_keyhandle(self, mock_complete_authn):
        mock_complete_authn.return_value = ({'keyHandle': 'wrong-handle'}, 'dummy-touch', 'dummy-counter')
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'mfa', action_dict=MFA_ACTION)
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    csrf_token = sess.get_csrf_token()
                    data = json.dumps({'csrf_token': csrf_token,
                                       'tokenResponse': 'dummy-response'})
                    response = client.post('/post-action', data=data, content_type=self.content_type_json)
                    data = json.loads(response.data.decode('utf-8'))
                    self.assertEqual(data['payload']['message'], "mfa.unknown-token")
                    self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    @patch('eduid_common.authn.fido_tokens.complete_authentication')
    def test_action_success(self, mock_complete_authn):
        mock_complete_authn.return_value = ({'keyHandle': 'test_key_handle'}, 'dummy-touch', 'dummy-counter')
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'mfa', action_dict=MFA_ACTION)
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    csrf_token = sess.get_csrf_token()
                    data = json.dumps({'csrf_token': csrf_token,
                                       'tokenResponse': 'dummy-response'})
                    response = client.post('/post-action', data=data, content_type=self.content_type_json)
                    self.assertEqual(response.status_code, 200)
                    data = json.loads(response.data)
                    self.assertEqual(data['payload']['message'], "actions.action-completed")
                    self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    @patch('eduid_common.authn.fido_tokens.complete_authentication')
    def test_action_webauthn_legacy_token(self, mock_complete_authn):
        #mock_complete_authn.return_value = ({'keyHandle': 'test_key_handle'},
        #        'dummy-touch', 'dummy-counter')
        #
        # Add a working U2F credential for this test
        u2f = U2F(version='U2F_V2',
                  keyhandle='V1vXqZcwBJD2RMIH2udd2F7R9NoSNlP7ZSPOtKHzS7n_rHFXcXbSpOoX__aUKyTR6jEC8Xv678WjXC5KEkvziA',
                  public_key='BHVTWuo3_D7ruRBe2Tw-m2atT2IOm_qQWSDreWShu3t21ne9c-DPSUdym-H-t7FcjV7rj1dSc3WSwaOJpFmkKxQ',
                  app_id='https://dev.eduid.se/u2f-app-id.json',
                  attest_cert='',
                  description='unit test U2F token'
                  )
        self.user.credentials.add(u2f)
        self.app.central_userdb.save(self.user, check_sync=False)

        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'mfa', action_dict=MFA_ACTION)
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    fido2_state = Fido2Server._make_internal_state(
                        base64.b64decode('3h/EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc='), 'preferred')
                    sess['eduid_webapp.actions.actions.mfa.webauthn.state'] = json.dumps(fido2_state)
                    csrf_token = sess.get_csrf_token()

                data = json.dumps({'csrf_token': csrf_token,
                                   'authenticatorData': 'mZ9k6EPHoJxJZNA+UuvM0JVoutZHmqelg9kXe/DSefgBAAAA/w==',
                                   'clientDataJSON': 'eyJjaGFsbGVuZ2UiOiIzaF9FQVpwWTI1eERkU0pDT014MUFCWkVBNU9k'+\
                                   'ejN5ZWpVSTNBVU5UUVdjIiwib3JpZ2luIjoiaHR0cHM6Ly9pZHAuZGV2LmVkdWlkLnNlIiwidH'+\
                                   'lwZSI6IndlYmF1dGhuLmdldCJ9',
                                   'credentialId': 'V1vXqZcwBJD2RMIH2udd2F7R9NoSNlP7ZSPOtKHzS7n/rHFXcXbSpOoX//'+\
                                                   'aUKyTR6jEC8Xv678WjXC5KEkvziA==',
                                   'signature': 'MEYCIQC5gM8inamJGUFKu3bNo4fT0jmJQuw33OSSXc242NCuiwIhAIWnVw2Sp'+\
                                                'ow72j6J92KaY2rLR6qSXEbLam09ZXbSkBnQ'}
                                  )

                self.app.config.fido2_rp_id = 'idp.dev.eduid.se'
                response = client.post('/post-action', data=data, content_type=self.content_type_json)
                self.assertEqual(response.status_code, 200)
                data = json.loads(response.data)
                self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_third_party_mfa_action_success(self):
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'mfa', action_dict=MFA_ACTION)
            with client.session_transaction() as sess:
                sess.mfa_action.success = True
                sess.mfa_action.issuer = 'https://issuer-entity-id.example.com'
                sess.mfa_action.authn_instant = '2019-03-21T16:26:17Z'
                sess.mfa_action.authn_context = 'http://id.elegnamnden.se/loa/1.0/loa3'

            response = client.get('/redirect-action')
            self.assertEqual(response.status_code, 302)
            db_actions = self.app.actions_db.get_actions(self.user.eppn, 'mock-session')
            self.assertTrue(db_actions[0].result['success'])
            self.assertEqual(db_actions[0].result['issuer'], 'https://issuer-entity-id.example.com')
            self.assertEqual(db_actions[0].result['authn_instant'], '2019-03-21T16:26:17Z')
            self.assertEqual(db_actions[0].result['authn_context'], 'http://id.elegnamnden.se/loa/1.0/loa3')

    def test_third_party_mfa_action_failure(self):
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'mfa', action_dict=MFA_ACTION)

            response = client.get('/redirect-action')
            self.assertEqual(response.status_code, 302)
            db_actions = self.app.actions_db.get_actions(self.user.eppn, 'mock-session')
            self.assertIsNone(db_actions[0].result)
