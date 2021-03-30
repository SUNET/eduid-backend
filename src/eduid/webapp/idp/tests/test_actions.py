#!/usr/bin/python
#
# Copyright (c) 2014 NORDUnet A/S
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
# Author : Enrique Perez <enrique@cazalla.net>
#

import logging
from datetime import datetime
from typing import cast

import bson
from mock import patch

from vccs_client import VCCSClient

from eduid.userdb.credentials import U2F, Webauthn
from eduid.userdb.idp import IdPUser
from eduid.userdb.tou import ToUEvent
from eduid.webapp.common.session.logindata import SSOLoginData
from eduid.webapp.idp.mfa_action import RESULT_CREDENTIAL_KEY_NAME
from eduid.webapp.idp.mfa_action import add_actions as mfa_add_actions
from eduid.webapp.idp.tests.test_app import LoginState
from eduid.webapp.idp.tests.test_SSO import SWAMID_AL2, SSOIdPTests
from eduid.webapp.idp.tests.test_SSO import cc as CONTEXTCLASSREFS
from eduid.webapp.idp.tou_action import add_actions as tou_add_actions

logger = logging.getLogger(__name__)

# local = cherrypy.lib.httputil.Host('127.0.0.1', 50000, "")
# remote = cherrypy.lib.httputil.Host('127.0.0.1', 50001, "")


class TestActions(SSOIdPTests):
    def setUp(self):
        super().setUp()

        self.actions = self.app.actions_db
        self.mock_session_key = 'mock-session'

        # setup some test data
        self.test_action = self.actions.add_action(self.test_user.eppn, action_type='dummy', preference=100, params={})

    def update_config(self, config):
        config = super().update_config(config)
        config.update(
            {
                'tou_version': 'mock-version',
                'base_url': 'https://unittest-idp.example.edu/',
                'action_plugins': ['tou', 'mfa'],
            }
        )
        return config

    @property
    def num_actions(self):
        """ Return the current number of actions for the test user in the test session """
        return len(self.actions.get_actions(self.test_user.eppn, self.mock_session_key))

    def _test_no_actions(self, tou: ToUEvent):

        # Remove the standard test_action from the database
        self.actions.remove_action_by_id(self.test_action.action_id)

        self.test_user.tou.add(tou)
        self.amdb.save(self.test_user, check_sync=False)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S5_LOGGED_IN

    def test_no_actions_touevent_from_dict(self):
        # Register user acceptance for the ToU version in use
        tou = ToUEvent.from_dict(
            dict(
                version=self.app.conf.tou_version,
                created_by='unit test',
                created_ts=datetime.utcnow(),
                event_id=bson.ObjectId(),
            )
        )
        self._test_no_actions(tou)

    def test_no_actions_touevent_init(self):
        # Register user acceptance for the ToU version in use
        tou = ToUEvent(version=self.app.conf.tou_version, created_by='unit test', event_id=str(bson.ObjectId()))
        self._test_no_actions(tou)

    def test_add_action(self):
        """ Test that we are redirected to the actions app when there is an action for the user (self.test_action) """

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S3_REDIRECT_LOGGED_IN

        assert self.app.conf.actions_app_uri in result.response.location

    def test_add_mfa_action_no_key(self):
        self.actions.remove_action_by_id(self.test_action.action_id)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            assert self.num_actions == 0
            assert mfa_add_actions(self.test_user, mock_ticket) is None
            assert self.num_actions == 0

    def test_add_mfa_action_no_key_required_mfa(self):
        self.actions.remove_action_by_id(self.test_action.action_id)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(
                req_class_ref=CONTEXTCLASSREFS['REFEDS_MFA'], key=self.mock_session_key
            )
            assert self.num_actions == 0
            action = mfa_add_actions(self.test_user, mock_ticket)
            assert action.action_type == 'mfa'
            assert self.num_actions == 1

    def test_add_mfa_action_old_key(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        u2f = U2F(
            version='U2F_V2',
            app_id='https://dev.eduid.se/u2f-app-id.json',
            keyhandle='test_key_handle',
            public_key='test_public_key',
            attest_cert='test_attest_cert',
            description='test_description',
        )
        self.test_user.credentials.add(u2f)
        self.amdb.save(self.test_user, check_sync=False)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            assert self.num_actions == 0
            action = mfa_add_actions(self.test_user, mock_ticket)
            assert action.action_type == 'mfa'
            assert self.num_actions == 1

    def test_add_mfa_action_new_key(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        webauthn = Webauthn(
            keyhandle='test_key_handle',
            credential_data='test_credential_data',
            app_id='https://dev.eduid.se/u2f-app-id.json',
            attest_obj='test_attest_obj',
            description='test_description',
        )
        self.test_user.credentials.add(webauthn)
        self.amdb.save(self.test_user, check_sync=False)

        mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)

        with self.app.app_context():
            assert self.num_actions == 0
            action = mfa_add_actions(self.test_user, mock_ticket)
            assert action.action_type == 'mfa'
            assert self.num_actions == 1

    def test_add_mfa_action_no_db(self):
        """ Make sure a user doesn't get stuck trying to log in if there is no action db """
        self.actions.remove_action_by_id(self.test_action.action_id)
        webauthn = Webauthn(
            keyhandle='test_key_handle',
            credential_data='test_credential_data',
            app_id='https://dev.eduid.se/u2f-app-id.json',
            attest_obj='test_attest_obj',
            description='test_description',
        )
        self.test_user.credentials.add(webauthn)
        self.amdb.save(self.test_user, check_sync=False)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            self.app.actions_db = None
            assert self.num_actions == 0
            assert mfa_add_actions(self.test_user, mock_ticket) is None
        # ensure no action was added when self.app.actions_db is None
        assert self.num_actions == 0

    def _test_add_2nd_mfa_action(
        self, success=True, authn_context=True, cred_key=None, expected_num_actions=0
    ) -> SSOLoginData:
        self.actions.remove_action_by_id(self.test_action.action_id)
        webauthn = Webauthn(
            keyhandle='test_key_handle',
            credential_data='test_credential_data',
            app_id='https://dev.eduid.se/u2f-app-id.json',
            attest_obj='test_attest_obj',
            description='test_description',
        )
        self.test_user.credentials.add(webauthn)
        self.amdb.save(self.test_user, check_sync=False)
        cred = self.test_user.credentials.filter(Webauthn).to_list()[0]
        if cred_key is None:
            cred_key = cred.key
        completed_action = self.actions.add_action(
            self.test_user.eppn, action_type='mfa', preference=100, params={}, session=self.mock_session_key
        )
        completed_action.result = {
            'cred_key': cred_key,
            'issuer': 'dummy-issuer',
            'success': success,
            'authn_context': authn_context,
        }
        self.actions.update_action(completed_action)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            action = mfa_add_actions(cast(IdPUser, self.test_user), mock_ticket)
            if expected_num_actions != 0:
                assert action is not None
                assert action.action_type == 'mfa'
            else:
                assert action is None
            assert self.num_actions == expected_num_actions
        return mock_ticket

    def test_add_mfa_action_already_authn(self):
        self._test_add_2nd_mfa_action(expected_num_actions=0)

    def test_add_mfa_action_already_authn_not(self):
        ticket = self._test_add_2nd_mfa_action(success=False, expected_num_actions=2)
        self.assertEqual(len(ticket.mfa_action_creds), 0)

    def test_add_2nd_mfa_action_no_context(self):
        ticket = self._test_add_2nd_mfa_action(authn_context=False, expected_num_actions=0)
        self.assertEqual(len(ticket.mfa_action_creds), 1)

    def test_add_2nd_mfa_action_no_context_wrong_key(self):
        ticket = self._test_add_2nd_mfa_action(authn_context=False, cred_key='wrong key', expected_num_actions=2)
        self.assertEqual(len(ticket.mfa_action_creds), 0)

    def test_add_tou_action(self):
        self.actions.remove_action_by_id(self.test_action.action_id)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            assert self.num_actions == 0
            action = tou_add_actions(self.test_user, mock_ticket)
            assert action.action_type == 'tou'
            assert self.num_actions == 1

    def test_add_tou_action_already_accepted(self):
        event_id = bson.ObjectId()
        self.test_user.tou.add(
            ToUEvent(
                version='mock-version',
                created_by='test_tou_plugin',
                created_ts=datetime.utcnow(),
                event_id=str(event_id),
            )
        )
        self.actions.remove_action_by_id(self.test_action.action_id)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            assert self.num_actions == 0
            assert tou_add_actions(self.test_user, mock_ticket) is None
            assert self.num_actions == 0

    def test_add_tou_action_already_accepted_other_version(self):
        event_id = bson.ObjectId()
        self.test_user.tou.add(
            ToUEvent(
                version='mock-version-2',
                created_by='test_tou_plugin',
                created_ts=datetime.utcnow(),
                event_id=str(event_id),
            )
        )
        self.actions.remove_action_by_id(self.test_action.action_id)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            assert self.num_actions == 0
            action = tou_add_actions(self.test_user, mock_ticket)
            assert action.action_type == 'tou'
            assert self.num_actions == 1

    def test_add_tou_action_already_action(self):
        self.app.actions_db.add_action(
            self.test_user.eppn, action_type='tou', preference=100, params={'version': 'mock-version'}
        )
        self.actions.remove_action_by_id(self.test_action.action_id)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            assert self.num_actions == 1
            assert tou_add_actions(self.test_user, mock_ticket) is None
            assert self.num_actions == 1

    def test_add_tou_action_already_action_other_version(self):
        self.app.actions_db.add_action(
            self.test_user.eppn, action_type='tou', preference=100, params={'version': 'mock-version-2'}
        )
        self.actions.remove_action_by_id(self.test_action.action_id)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            assert self.num_actions == 1
            action = tou_add_actions(self.test_user, mock_ticket)
            assert action.action_type == 'tou'
            assert self.num_actions == 2

    def test_add_tou_action_should_reaccept(self):
        event_id = bson.ObjectId()
        self.test_user.tou.add(
            ToUEvent(
                version='mock-version',
                created_by='test_tou_plugin',
                created_ts=datetime(2015, 9, 24, 1, 1, 1, 111111),
                modified_ts=datetime(2015, 9, 24, 1, 1, 1, 111111),
                event_id=str(event_id),
            )
        )
        self.actions.remove_action_by_id(self.test_action.action_id)

        with self.app.app_context():
            mock_ticket = self._make_login_ticket(req_class_ref=SWAMID_AL2, key=self.mock_session_key)
            assert self.num_actions == 0
            action = tou_add_actions(self.test_user, mock_ticket)
            assert action.action_type == 'tou'
            assert self.num_actions == 1

    def test_mfa_action_fake_completion(self):
        """ Test returning from actions after completing an MFA actions """

        # Only bother with MFA actions in this test, so mark the ToU as registered already
        event_id = bson.ObjectId()
        self.test_user.tou.add(
            ToUEvent(
                version='mock-version',
                created_by='test_tou_plugin',
                created_ts=datetime.utcnow(),
                event_id=str(event_id),
            )
        )
        self.actions.remove_action_by_id(self.test_action.action_id)

        # Add an MFA credential to the user
        webauthn = Webauthn(
            keyhandle='test_key_handle',
            credential_data='test_credential_data',
            app_id='https://dev.eduid.se/u2f-app-id.json',
            attest_obj='test_attest_obj',
            description='test_description',
        )
        self.test_user.credentials.add(webauthn)
        self.amdb.save(self.test_user, check_sync=False)

        # Patch the VCCSClient so we do not need a vccs server
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True
            result = self._try_login()

        assert result.reached_state == LoginState.S3_REDIRECT_LOGGED_IN
        assert result.sso_cookie_val is not None

        assert self.app.conf.actions_app_uri in result.response.location

        actions = self.actions.get_actions(eppn_or_userid=self.test_user.eppn, session=None)
        logger.info(f'\n\n\nActions for user {self.test_user.eppn} now: {actions}\n\n\n')

        # register a result for all MFA actions
        for this in actions:
            if this.action_type == 'mfa':
                this.result = {'success': True, RESULT_CREDENTIAL_KEY_NAME: webauthn.key}
                self.actions.update_action(this)

        logger.info(f'Retrying URL {result.url}')

        # Retry the last location
        cookies = result.response.headers.get('Set-Cookie')
        resp = self.browser.get(result.url, headers={'Cookie': cookies})
        assert resp.status_code == 200

        # now load the SSO session and make sure it has been updated with the MFA credential
        sso_session = self.get_sso_session(result.sso_cookie_val)
        assert sso_session is not None

        assert len(sso_session.authn_credentials) == 2
        expected_credentials_used = [x.key for x in self.test_user.credentials.to_list()]
        credentials_used = [x.cred_id for x in sso_session.authn_credentials]
        assert credentials_used == expected_credentials_used
        assert sso_session.eppn == self.test_user.eppn
        assert sso_session.user_id == self.test_user.user_id
        assert sso_session.minutes_old <= 1
        assert sso_session.external_mfa is None
