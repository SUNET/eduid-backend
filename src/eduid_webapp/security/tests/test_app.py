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

from flask import current_app
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.api.utils import retrieve_modified_ts
from eduid_webapp.security.app import security_init_app


class SecurityTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropiate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English','sv': 'Svenska'},
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
            'PASSWORD_LENGTH': 12,
            'PASSWORD_ENTROPY': 25,
            'CHPASS_TIMEOUT': 600,
            'EDUID_SITE_NAME': 'eduID',
            'EDUID_SITE_URL': 'https://www.eduid.se/',
        })
        return config

    def init_data(self):
        self.app.dashboard_userdb.save(self.test_user, check_sync=False)
        retrieve_modified_ts(self.test_user)

    def test_get_credentials(self):
        response = self.browser.get('/credentials')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/credentials')

            sec_data = json.loads(response2.data)
            self.assertEqual(sec_data['type'],
                             'GET_SECURITY_CREDENTIALS_SUCCESS')

    def test_get_suggested(self):
        response = self.browser.get('/suggested-password')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/suggested-password')

            passwd = json.loads(response2.data)
            self.assertEqual(passwd['type'],
                             'GET_SECURITY_SUGGESTED_PASSWORD_SUCCESS')

    def test_change_passwd_no_data(self):
        response = self.browser.post('/change-password')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.post('/change-password')

            sec_data = json.loads(response2.data)
            self.assertEqual(sec_data['type'],
                             "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    def test_change_passwd_no_reauthn(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                            'csrf_token': sess.get_csrf_token(),
                            'new_password': '1234',
                            'old_password': '5678'
                            }
                response2 = client.post('/change-password', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                sec_data = json.loads(response2.data)
                self.assertEqual(sec_data['type'],
                                 "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    def test_change_passwd_stale(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                sess['reauthn-for-chpass'] = True
                with self.app.test_request_context():
                    data = {
                            'csrf_token': sess.get_csrf_token(),
                            'new_password': '1234',
                            'old_password': '5678'
                            }
                response2 = client.post('/change-password', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                sec_data = json.loads(response2.data)
                self.assertEqual(sec_data['type'],
                                 "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_change_passwd_no_csrf(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.security.views.add_credentials',
                           return_value=True):
                    sess['reauthn-for-chpass'] = int(time.time())
                    data = {
                            'new_password': '1234',
                            'old_password': '5678'
                            }
                    response2 = client.post('/change-password', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    sec_data = json.loads(response2.data)
                    self.assertEqual(sec_data['type'],
                                     "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_change_passwd_wrong_csrf(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.security.views.add_credentials', return_value=True):
                    sess['reauthn-for-chpass'] = int(time.time())
                    data = {
                            'csrf_token': '0000',
                            'new_password': '1234',
                            'old_password': '5678'
                            }
                    response2 = client.post('/change-password', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    sec_data = json.loads(response2.data)
                    self.assertEqual(sec_data['type'],
                                     "POST_SECURITY_CHANGE_PASSWORD_FAIL")

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_change_passwd(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.security.views.add_credentials', return_value=True):
                    sess['reauthn-for-chpass'] = int(time.time())
                    with self.app.test_request_context():
                        data = {
                                'csrf_token': sess.get_csrf_token(),
                                'new_password': '1234',
                                'old_password': '5678'
                                }
                    response2 = client.post('/change-password', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    sec_data = json.loads(response2.data)
                    self.assertEqual(sec_data['type'],
                                     "POST_SECURITY_CHANGE_PASSWORD_SUCCESS")

    def test_delete_account_no_csrf(self):
        response = self.browser.post('/terminate-account')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.post('/terminate-account')

            rdata = json.loads(response2.data)
            self.assertEqual(rdata['type'],
                             'POST_SECURITY_TERMINATE_ACCOUNT_FAIL')

    def test_delete_account_wrong_csrf(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            data = {
                    'csrf_token': '1234',
                    }
            response2 = client.post('/terminate-account', data=json.dumps(data),
                                    content_type=self.content_type_json)

            rdata = json.loads(response2.data)
            self.assertEqual(rdata['type'],
                             'POST_SECURITY_TERMINATE_ACCOUNT_FAIL')

    def test_delete_account(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                            'csrf_token': sess.get_csrf_token(),
                            }
                response2 = client.post('/terminate-account', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

            rdata = json.loads(response2.data)

            self.assertEqual(rdata['payload']['location'],
                             'http://test.localhost/terminate?next=%2Faccount-terminated')
            self.assertEqual(rdata['type'],
                             'POST_SECURITY_TERMINATE_ACCOUNT_SUCCESS')

    def test_account_terminated_no_authn(self):
        response = self.browser.get('/account-terminated')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

    def test_account_terminated_no_reauthn(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/account-terminated')
            
            self.assertEqual(response2.status_code, 400)

    def test_account_terminated_stale(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                sess['reauthn-for-termination'] = 0
                response2 = client.get('/account-terminated')
                
                self.assertEqual(response2.status_code, 200)
                rdata = json.loads(response2.data)

                self.assertEqual(rdata['type'],
                                 'GET_SECURITY_ACCOUNT_TERMINATED_FAIL')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.security.views.revoke_all_credentials')
    def test_account_terminated(self, mock_revoke, mock_sync):
        mock_revoke.return_value = True
        mock_sync.return_value = True
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                sess['reauthn-for-termination'] = int(time.time())
                response2 = client.get('/account-terminated')

                self.assertEqual(response2.status_code, 302)

                self.assertEqual(response2.location,
                                 'https://www.eduid.se/')
