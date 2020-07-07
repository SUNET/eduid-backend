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

import base64
import json
from typing import Optional

from bson import ObjectId
from fido2.server import Fido2Server
from mock import patch

from eduid_common.session import session
from eduid_userdb.credentials import U2F
from eduid_userdb.fixtures.users import mocked_user_standard

from eduid_webapp.actions.actions.mfa import Plugin
from eduid_webapp.actions.helpers import ActionsMsg
from eduid_webapp.actions.testing import ActionsTestCase, MockIdPContext

__author__ = 'ft'

MFA_ACTION = {
    '_id': ObjectId('234567890123456789012301'),
    'eppn': mocked_user_standard.eppn,
    'action': 'mfa',
    'session': 'mock-session',
    'preference': 1,
    'params': {},
}


def add_actions(context, user, ticket):
    """
    This is a stripped down version of eduid_idp.mfa_action.add_actions
    that adds the action unconditionally.
    """
    action = context.actions_db.add_action(user.eppn, action_type='mfa', preference=1, session=ticket.key, params={})
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
        u2f = U2F.from_dict(
            dict(
                version='U2F_V2',
                app_id='https://dev.eduid.se/u2f-app-id.json',
                keyhandle='test_key_handle',
                public_key='test_public_key',
                attest_cert='test_attest_cert',
                description='test_description',
            )
        )
        self.user.credentials.add(u2f)
        self.app.central_userdb.save(self.user, check_sync=False)

    def update_actions_config(self, config):
        config['environment'] = 'dev'
        config['action_plugins'] = ['mfa']
        config['mfa_testing'] = False
        config['u2f_app_id'] = 'https://example.com'
        config['u2f_valid_facets'] = ['https://dashboard.dev.eduid.se', 'https://idp.dev.eduid.se']
        config['fido2_rp_id'] = 'idp.example.com'
        config['eidas_url'] = 'https://eidas.dev.eduid.se/mfa-authentication'
        config['mfa_authn_idp'] = 'https://eidas-idp.example.com'
        return config

    # parameterized test methods

    def _get_mfa_action(self, idp_session: Optional[str] = None):
        """
        GET info for the actions service when there is a mfa pending action

        :param idp_session: to control the action's session used for authn
        """
        mock_session = 'mock-session'
        if idp_session is None:
            idp_session = mock_session
        mock_idp_app = MockIdPContext(self.app.actions_db)
        with self.app.test_request_context('/get-actions'):
            add_actions(mock_idp_app, self.user, MockTicket(mock_session))
            self.authenticate(idp_session=idp_session)
            response = self.app.dispatch_request()
            return json.loads(response)

    def _get_config(self):
        """
        Get configuration for the actions app for a mfa action
        """
        with self.app.test_request_context('/config'):
            mock_idp_app = MockIdPContext(self.app.actions_db)
            add_actions(mock_idp_app, self.user, MockTicket('mock-session'))
            self.authenticate(idp_session='mock-session')
            response = self.app.dispatch_request()
            return json.loads(response.data)

    @patch('eduid_common.authn.fido_tokens.complete_authentication')
    def _action(
        self,
        mock_complete_authn,
        data1: Optional[dict] = None,
        keyhandle: str = 'test_key_handle',
        fido2_state: str = '',
    ):
        """
        POST data reflecting the user's response to the mfa request.

        :param data1: to control the POSTed data
        :param keyhandle: to control the mocked return vaalue of `complete_authentication`
        :param fido2state: to control the fido2 state kept in the session
        """
        mock_complete_authn.return_value = ({'keyHandle': keyhandle}, 'dummy-touch', 'dummy-counter')
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'mfa', action_dict=MFA_ACTION)
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    sess['eduid_webapp.actions.actions.mfa.webauthn.state'] = fido2_state
                    csrf_token = sess.get_csrf_token()
                    data = {
                        'csrf_token': csrf_token,
                    }
                    if data1 is not None:
                        data.update(data1)
                    return client.post('/post-action', data=json.dumps(data), content_type=self.content_type_json)

    def _third_party_mfa_action_success(self, prepare_session: bool = True):
        """
        When a 3rd party successfully validates the mfa token, it is kept in the session,
        and the actions app needs to be aware of it.

        :param prepare_session: whether to add 3rd party mfa info to the session
        """
        with self.session_cookie(self.browser) as client:
            self.prepare(client, Plugin, 'mfa', action_dict=MFA_ACTION)
            if prepare_session:
                with client.session_transaction() as sess:
                    sess.mfa_action.success = True
                    sess.mfa_action.issuer = 'https://issuer-entity-id.example.com'
                    sess.mfa_action.authn_instant = '2019-03-21T16:26:17Z'
                    sess.mfa_action.authn_context = 'http://id.elegnamnden.se/loa/1.0/loa3'

            response = client.get('/redirect-action')
            self.assertEqual(response.status_code, 302)
            assert self.user is not None  # assure mypy that self.user has been initialised (in setUp)
            return self.app.actions_db.get_actions(self.user.eppn, 'mock-session')

    # actual tests

    def test_get_config(self):
        data = self._get_config()
        assert 'webauthn_options' in data['payload']
        s = data['payload']['webauthn_options']
        _decoded = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
        # _decoded is still CBOR encoded, so we just check for some known strings
        assert b'publicKey' in _decoded
        assert b'idp.example.com' in _decoded
        assert b'challenge' in _decoded
        self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_get_config_no_user(self):
        self.app.central_userdb.remove_user_by_id(self.user.user_id)
        data = self._get_config()
        self.assertEqual(data['payload']['message'], 'mfa.user-not-found')

    def test_get_mfa_action(self):
        data = self._get_mfa_action()
        self.assertEqual(data['action'], True)
        self.assertEqual('http://example.com/bundles/eduid_action.mfa-bundle.dev.js', data['url'])
        self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_get_mfa_action_wrong_session(self):
        data = self._get_mfa_action(idp_session='wrong-session')
        self.assertEqual(data['action'], False)
        self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_action_success(self):
        data1 = {'tokenResponse': 'dummy-response'}
        response = self._action(data1=data1)
        self._check_success_response(
            response, type_='POST_ACTIONS_POST_ACTION_SUCCESS', msg=ActionsMsg.action_completed
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['payload']['message'], "actions.action-completed")
        self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_action_no_token_response(self):
        response = self._action()
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['payload']['message'], "mfa.no-token-response")
        self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_action_wrong_keyhandle(self):
        data1 = {'tokenResponse': 'dummy-response'}
        response = self._action(data1=data1, keyhandle='wrong-keyhandle')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['payload']['message'], "mfa.unknown-token")
        self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_action_wrong_csrf(self):
        data1 = {
            'tokenResponse': 'dummy-response',
            'csrf_token': 'wrong-token',
        }
        response = self._action(data1=data1)
        self._check_error_response(
            response, type_='POST_ACTIONS_POST_ACTION_FAIL', error={'csrf_token': ['CSRF failed to validate'],},
        )

    @patch('eduid_common.authn.fido_tokens.complete_authentication')
    def test_action_webauthn_legacy_token(self, mock_complete_authn):
        # mock_complete_authn.return_value = ({'keyHandle': 'test_key_handle'},
        #        'dummy-touch', 'dummy-counter')
        #
        # Add a working U2F credential for this test
        u2f = U2F.from_dict(
            dict(
                version='U2F_V2',
                keyhandle='V1vXqZcwBJD2RMIH2udd2F7R9NoSNlP7ZSPOtKHzS7n_rHFXcXbSpOoX__aUKyTR6jEC8Xv678WjXC5KEkvziA',
                public_key='BHVTWuo3_D7ruRBe2Tw-m2atT2IOm_qQWSDreWShu3t21ne9c-DPSUdym-H-t7FcjV7rj1dSc3WSwaOJpFmkKxQ',
                app_id='https://dev.eduid.se/u2f-app-id.json',
                attest_cert='',
                description='unit test U2F token',
            )
        )
        self.user.credentials.add(u2f)
        self.app.central_userdb.save(self.user, check_sync=False)

        fido2_state = json.dumps(
            Fido2Server._make_internal_state(
                base64.b64decode('3h/EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc='), 'preferred'
            )
        )
        self.app.config.fido2_rp_id = 'idp.dev.eduid.se'

        data1 = {
            'authenticatorData': 'mZ9k6EPHoJxJZNA+UuvM0JVoutZHmqelg9kXe/DSefgBAAAA/w==',
            'clientDataJSON': (
                'eyJjaGFsbGVuZ2UiOiIzaF9FQVpwWTI1eERkU0pDT014MUFCWkVBNU9k'
                'ejN5ZWpVSTNBVU5UUVdjIiwib3JpZ2luIjoiaHR0cHM6Ly9pZHAuZGV2LmVkdWlkLnNlIiwidH'
                'lwZSI6IndlYmF1dGhuLmdldCJ9'
            ),
            'credentialId': (
                'V1vXqZcwBJD2RMIH2udd2F7R9NoSNlP7ZSPOtKHzS7n/rHFXcXbSpOoX//aUKyTR6jEC8Xv678WjXC5KEkvziA=='
            ),
            'signature': (
                'MEYCIQC5gM8inamJGUFKu3bNo4fT0jmJQuw33OSSXc242NCuiwIhAIWnVw2Spow72j6J92KaY2rLR6qSXEbLam09ZXbSkBnQ'
            ),
        }

        response = self._action(data1=data1, fido2_state=fido2_state)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.app.actions_db.get_actions(self.user.eppn, 'mock-session')), 1)

    def test_third_party_mfa_action_success(self):
        db_actions = self._third_party_mfa_action_success()
        self.assertTrue(db_actions[0].result['success'])
        self.assertEqual(db_actions[0].result['issuer'], 'https://issuer-entity-id.example.com')
        self.assertEqual(db_actions[0].result['authn_instant'], '2019-03-21T16:26:17Z')
        self.assertEqual(db_actions[0].result['authn_context'], 'http://id.elegnamnden.se/loa/1.0/loa3')

    def test_third_party_mfa_action_failure(self):
        db_actions = self._third_party_mfa_action_success(prepare_session=False)
        self.assertIsNone(db_actions[0].result)
