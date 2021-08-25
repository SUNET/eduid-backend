# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2018 SUNET
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
from datetime import timedelta
from typing import Any, Dict, Mapping, Optional
from uuid import uuid4

from mock import patch

from eduid.common.misc.timeutil import utc_now
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.session.namespaces import AuthnRequestRef, SP_AuthnRequest
from eduid.webapp.security.app import SecurityApp, security_init_app
from eduid.webapp.security.helpers import SecurityMsg


class SecurityTests(EduidAPITestCase):

    app: SecurityApp

    def setUp(self):
        super(SecurityTests, self).setUp(copy_user_to_private=True)

        self.test_user_eppn = 'hubba-bubba'
        self.test_user_nin = '197801011235'

    def load_app(self, config: Mapping[str, Any]) -> SecurityApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'password_length': 12,
                'password_entropy': 25,
                'chpass_timeout': 600,
                'eduid_site_name': 'eduID',
                'eduid_site_url': 'https://www.eduid.se/',
                'u2f_app_id': 'foo',
                'u2f_valid_facets': [],
                'fido2_rp_id': 'https://test.example.edu',
                'vccs_url': 'https://vccs',
                'dashboard_url': 'https://dashboard/',
            }
        )
        return config

    # parameterized test methods

    def _delete_account(self, data1: Optional[dict] = None):
        """
        Send a POST request to the endpoint to start the process to terminate the account.
        After visiting this endpoint, the user would be sent to re-authenticate before being
        able to actually delete the account.

        :param data1: to control the data sent in the POST.
        """
        response = self.browser.post('/terminate-account')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        'csrf_token': sess.get_csrf_token(),
                    }
                if data1 is not None:
                    data.update(data1)

            return client.post('/terminate-account', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid.common.rpc.mail_relay.MailRelay.sendmail')
    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    @patch('eduid.webapp.security.views.security.revoke_all_credentials')
    def _account_terminated(
        self,
        mock_revoke: Any,
        mock_sync: Any,
        mock_sendmail: Any,
        reauthn: Optional[int] = None,
        sendmail_side_effect: Any = None,
    ):
        """
        Send a GET request to the endpoint to actually terminate the account,
        mocking re-authentication by setting a timestamp in the session.

        :param reauthn: age of authn_instant to set in the session to mock re-authentication.
        """
        mock_revoke.return_value = True
        mock_sync.return_value = True
        mock_sendmail.return_value = True
        if sendmail_side_effect:
            mock_sendmail.side_effect = sendmail_side_effect

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            if reauthn is not None:
                # Add authn data faking a reauthn event has taken place for this action
                with client.session_transaction() as sess:
                    _authn_id = AuthnRequestRef(str(uuid4()))
                    sess.authn.sp.authns[_authn_id] = SP_AuthnRequest(
                        post_authn_action=AuthnAcsAction.terminate_account,
                        redirect_url='/test',
                        authn_instant=utc_now() - timedelta(seconds=reauthn),
                    )
            return client.get('/account-terminated')

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def _remove_nin(self, mock_request_user_sync: Any, data1: Optional[dict] = None, unverify: bool = True):
        """
        Send a POST request to remove a NIN from the test user, possibly
        unverifying his verified NIN.

        :param data1: to control the data that is POSTed
        :param unverify: whether to unverify the test user NIN.
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user
        assert user.nins.count == 2
        assert len(user.nins.verified) == 2

        if unverify:
            nin = user.nins.find(self.test_user_nin)
            assert nin is not None
            nin.is_primary = False
            nin.is_verified = False
            self.app.central_userdb.save(user, check_sync=False)

            self.assertEqual(len(user.nins.verified), 1)

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {'nin': self.test_user_nin, 'csrf_token': sess.get_csrf_token()}
                if data1 is not None:
                    data.update(data1)

                return client.post('/remove-nin', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def _add_nin(self, mock_request_user_sync: Any, data1: Optional[dict] = None, remove: bool = True):
        """
        Send a POST request to add a NIN to the test user, possibly removing his primary, verified NIN.

        :param data1: to control the data that is POSTed
        :param remove: whether to actually remove the NIN from the test user before sending the request.
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user is not None
        assert user.nins.count == 2
        assert len(user.nins.verified) == 2

        if remove:
            user.nins.remove(self.test_user_nin)
            self.app.central_userdb.save(user, check_sync=False)
            self.assertEqual(len(user.nins.verified), 1)

        with self.session_cookie(self.browser, self.test_user_eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {'nin': self.test_user_nin, 'csrf_token': sess.get_csrf_token()}
                if data1:
                    data.update(data1)

                return client.post('/add-nin', data=json.dumps(data), content_type=self.content_type_json)

    # actual tests

    def test_delete_account_no_csrf(self):
        data1 = {'csrf_token': ''}
        response = self._delete_account(data1=data1)
        self.assertEqual(response.json['type'], 'POST_SECURITY_TERMINATE_ACCOUNT_FAIL')
        self.assertEqual(response.json['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_delete_account_wrong_csrf(self):
        data1 = {'csrf_token': 'wrong-token'}
        response = self._delete_account(data1=data1)
        self.assertEqual(response.json['type'], 'POST_SECURITY_TERMINATE_ACCOUNT_FAIL')
        self.assertEqual(response.json['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_delete_account(self):
        response = self._delete_account()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json['payload']['location'], 'http://test.localhost/terminate?next=%2Faccount-terminated'
        )
        self.assertEqual(response.json['type'], 'POST_SECURITY_TERMINATE_ACCOUNT_SUCCESS')

    def test_account_terminated_no_authn(self):
        response = self.browser.get('/account-terminated')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

    def test_account_terminated_no_reauthn(self):
        response = self._account_terminated()
        self._check_error_response(response, type_='GET_SECURITY_ACCOUNT_TERMINATED_FAIL', msg=SecurityMsg.no_reauthn)

    def test_account_terminated_stale(self):
        response = self._account_terminated(reauthn=1200)
        self._check_error_response(
            response, type_='GET_SECURITY_ACCOUNT_TERMINATED_FAIL', msg=SecurityMsg.stale_reauthn
        )

    @patch('eduid.webapp.security.views.security.send_termination_mail')
    def test_account_terminated_sendmail_fail(self, mock_send: Any):
        from eduid.webapp.common.api.exceptions import MsgTaskFailed

        mock_send.side_effect = MsgTaskFailed()
        response = self._account_terminated(reauthn=50)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'http://test.localhost/services/authn/logout?next=https://eduid.se')

    def test_account_terminated_mail_fail(self):
        from eduid.webapp.common.api.exceptions import MsgTaskFailed

        response = self._account_terminated(sendmail_side_effect=MsgTaskFailed(), reauthn=8)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'http://test.localhost/services/authn/logout?next=https://eduid.se')

    def test_account_terminated(self):
        response = self._account_terminated(reauthn=22)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, 'http://test.localhost/services/authn/logout?next=https://eduid.se')

    def test_remove_nin(self):
        response = self._remove_nin()
        self._check_success_response(
            response,
            type_='POST_SECURITY_REMOVE_NIN_SUCCESS',
            msg=SecurityMsg.rm_success,
            payload={'nins': [{'number': '197801011234', 'primary': True, 'verified': True}]},
        )

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(len(user.nins.verified), 1)

    def test_remove_not_existing_nin(self):
        response = self._remove_nin(data1={'nin': '190102031234'})
        self._check_success_response(
            response,
            type_='POST_SECURITY_REMOVE_NIN_SUCCESS',
            msg=SecurityMsg.rm_success,
            payload={
                'nins': [
                    {'number': '197801011234', 'primary': True, 'verified': True},
                    {'number': '197801011235', 'primary': False, 'verified': False},
                ]
            },
        )
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        assert user.nins.count == 2
        assert len(user.nins.verified) == 1

    @patch('eduid.webapp.security.views.security.remove_nin_from_user')
    def test_remove_nin_am_fail(self, mock_remove: Any):
        from eduid.webapp.common.api.exceptions import AmTaskFailed

        mock_remove.side_effect = AmTaskFailed()
        response = self._remove_nin()

        self.assertTrue(response.json['payload']['message'], "Temporary technical problems")

    def test_remove_nin_no_csrf(self):
        data1 = {'csrf_token': ''}
        response = self._remove_nin(data1=data1)

        self.assertTrue(response.json['payload']['error'])

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 2)
        self.assertEqual(len(user.nins.verified), 1)

    def test_remove_verified_nin(self):
        response = self._remove_nin(unverify=False)
        self._check_error_response(response, type_='POST_SECURITY_REMOVE_NIN_FAIL', msg=SecurityMsg.rm_verified)

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 2)
        self.assertEqual(len(user.nins.verified), 2)

    def test_add_nin(self):
        response = self._add_nin()

        self._check_success_response(
            response,
            type_='POST_SECURITY_ADD_NIN_SUCCESS',
            msg=SecurityMsg.add_success,
            payload={'nins': [{'number': '197801011234', 'primary': True, 'verified': True}]},
        )

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 2)
        self.assertEqual(len(user.nins.verified), 1)

    def test_add_existing_nin(self):
        response = self._add_nin(remove=False)

        self.assertFalse(response.json['payload']['success'])
        self.assertEqual(response.json['payload']['message'], 'nins.already_exists')

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 2)
        self.assertEqual(len(user.nins.verified), 2)

    @patch('eduid.webapp.security.views.security.add_nin_to_user')
    def test_add_nin_task_failed(self, mock_add):
        from eduid.webapp.common.api.exceptions import AmTaskFailed

        mock_add.side_effect = AmTaskFailed()
        response = self._add_nin()

        self.assertEqual(response.json['payload']['message'], 'Temporary technical problems')

    def test_add_nin_bad_csrf(self):
        data1 = {'csrf_token': 'bad-token'}
        response = self._add_nin(data1=data1, remove=False)

        self.assertTrue(response.json['payload']['error'])

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 2)
        self.assertEqual(len(user.nins.verified), 2)

    def test_add_invalid_nin(self):
        data1 = {'nin': '123456789'}
        response = self._add_nin(data1=data1, remove=False)
        self.assertIsNotNone(response.json['payload']['error']['nin'])

        self._check_error_response(
            response,
            type_='POST_SECURITY_ADD_NIN_FAIL',
            error={'nin': ['nin needs to be formatted as 18|19|20yymmddxxxx']},
        )
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 2)
        self.assertEqual(len(user.nins.verified), 2)

    # Tests below are for deprecated views (moved to the reset-password service),
    # to be removed whith the views

    def _get_credentials(self):
        response = self.browser.get('/credentials')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            return client.get('/credentials')

    def test_get_credentials(self):
        response = self._get_credentials()
        expected_payload = {
            'credentials': [
                {
                    'created_ts': '2013-09-02 10:23:25+00:00',
                    'credential_type': 'security.password_credential_type',
                    'description': None,
                    'key': '112345678901234567890123',
                    'success_ts': None,
                    'used_for_login': False,
                    'verified': False,
                }
            ],
        }
        self._check_success_response(response, type_='GET_SECURITY_CREDENTIALS_SUCCESS', payload=expected_payload)

    def _get_suggested(self):
        response = self.browser.get('/suggested-password')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            return client.get('/suggested-password')

    def test_get_suggested(self):
        response = self._get_suggested()

        passwd = json.loads(response.data)
        self.assertEqual(passwd['type'], 'GET_SECURITY_SUGGESTED_PASSWORD_SUCCESS')

    def test_change_passwd_no_data(self):
        response = self.browser.post('/change-password')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.post('/change-password')

            sec_data = json.loads(response2.data)
            self.assertEqual(sec_data['payload']['message'], 'chpass.no-data')
            self.assertEqual(sec_data['type'], "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    def test_change_passwd_no_reauthn(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    data = {
                        'csrf_token': sess.get_csrf_token(),
                        'new_password': 'j7/E >pO9 ,$Sr',
                        'old_password': '5678',
                    }
            response2 = client.post('/change-password', data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(response2, type_='POST_SECURITY_CHANGE_PASSWORD_FAIL', msg=SecurityMsg.no_reauthn)

    def test_change_passwd_stale(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with self.app.test_request_context():
                with client.session_transaction() as sess:
                    # Add authn data faking a reauthn event has taken place for this action (yesterday)
                    _authn_id = AuthnRequestRef(str(uuid4()))
                    sess.authn.sp.authns[_authn_id] = SP_AuthnRequest(
                        post_authn_action=AuthnAcsAction.change_password,
                        redirect_url='/test',
                        authn_instant=utc_now() - timedelta(days=1),
                    )
                    data = {
                        'csrf_token': sess.get_csrf_token(),
                        'new_password': 'j7/E >pO9 ,$Sr O0;&',
                        'old_password': '5678',
                    }
            response2 = client.post('/change-password', data=json.dumps(data), content_type=self.content_type_json)
        self._check_error_response(response2, type_='POST_SECURITY_CHANGE_PASSWORD_FAIL', msg=SecurityMsg.stale_reauthn)

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_change_passwd_no_csrf(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with patch('eduid.webapp.security.views.security.add_credentials', return_value=True):
                # with client.session_transaction() as sess:
                #    sess['reauthn-for-chpass'] = int(time.time())
                data = {'new_password': 'j7/E >pO9 ,$Sr O0;&', 'old_password': '5678'}
                response2 = client.post('/change-password', data=json.dumps(data), content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                sec_data = json.loads(response2.data)
                self.assertEqual(sec_data['payload']['message'], 'chpass.weak-password')
                self.assertEqual(sec_data['type'], "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_change_passwd_wrong_csrf(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with patch('eduid.webapp.security.views.security.add_credentials', return_value=True):
                with client.session_transaction() as sess:
                    # sess['reauthn-for-chpass'] = int(time.time())
                    data = {'csrf_token': '0000', 'new_password': 'j7/E >pO9 ,$Sr O0;&', 'old_password': '5678'}
                response2 = client.post('/change-password', data=json.dumps(data), content_type=self.content_type_json)

                sec_data = json.loads(response2.data)
                self.assertEqual(sec_data['payload']['message'], 'csrf.try_again')
                self.assertEqual(sec_data['type'], "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_change_passwd_weak(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with patch('eduid.webapp.security.views.security.add_credentials', return_value=True):
                with self.app.test_request_context():
                    with client.session_transaction() as sess:
                        # sess['reauthn-for-chpass'] = int(time.time())
                        data = {'csrf_token': sess.get_csrf_token(), 'new_password': '1234', 'old_password': '5678'}
                response2 = client.post('/change-password', data=json.dumps(data), content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                sec_data = json.loads(response2.data)
                self.assertEqual(sec_data['payload']['message'], 'chpass.weak-password')
                self.assertEqual(sec_data['type'], "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    @patch('eduid.common.rpc.am_relay.AmRelay.request_user_sync')
    def test_change_passwd(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with patch('eduid.webapp.security.views.security.add_credentials', return_value=True):
                with self.app.test_request_context():
                    with client.session_transaction() as sess:
                        # Add authn data faking a reauthn event has taken place for this action
                        _authn_id = AuthnRequestRef(str(uuid4()))
                        sess.authn.sp.authns[_authn_id] = SP_AuthnRequest(
                            post_authn_action=AuthnAcsAction.change_password,
                            redirect_url='/test',
                            authn_instant=utc_now() - timedelta(seconds=12),
                        )
                        data = {
                            'csrf_token': sess.get_csrf_token(),
                            'new_password': 'j7/E >pO9 ,$Sr O0;&',
                            'old_password': '5678',
                        }
                response2 = client.post('/change-password', data=json.dumps(data), content_type=self.content_type_json)
        self._check_success_response(
            response2, type_='POST_SECURITY_CHANGE_PASSWORD_SUCCESS', msg=SecurityMsg.chpass_password_changed2
        )
