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

from flask import current_app
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_common.api.utils import retrieve_modified_ts
from eduid_webapp.email.app import email_init_app


class EmailTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropiate flask
        app for this test case.
        """
        return email_init_app('emails', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English','sv': 'Svenska'},
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json',
                'MONGO_URI': config['MONGO_URI'],
            },
        })
        return config

    def init_data(self):
        self.app.email_proofing_userdb.save(self.test_user, check_sync=False)
        retrieve_modified_ts(self.test_user,
                dashboard_userdb=self.app.email_proofing_userdb)

    def test_get_all_emails(self):
        response = self.browser.get('/all')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/all')

            self.assertEqual(response.status_code, 302)

            email_data = json.loads(response2.data)

            self.assertEqual(email_data['type'], 'GET_EMAIL_ALL_SUCCESS')
            self.assertEqual(email_data['payload']['emails'][0].get('email'), 'johnsmith@example.com')
            self.assertEqual(email_data['payload']['emails'][0].get('verified'), True)
            self.assertEqual(email_data['payload']['emails'][1].get('email'), 'johnsmith2@example.com')
            self.assertEqual(email_data['payload']['emails'][1].get('verified'), False)

    def test_post_email_error_no_data(self):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302) # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.post('/new')

            self.assertEqual(response.status_code, 302)

            new_email_data = json.loads(response2.data)
            self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_FAIL')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def test_post_email(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_request_user_sync.return_value = True
        mock_code_verification.return_value = u'123456'
        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                data = {
                    'email': 'john-smith@example.com',
                    'verified': False,
                    'primary': False,
                    'csrf_token': sess.get_csrf_token()
                }

                response2 = client.post('/new', data=json.dumps(data),
                                       content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                new_email_data = json.loads(response2.data)

                self.assertEqual(new_email_data['type'], 'POST_EMAIL_NEW_SUCCESS')
                self.assertEqual(new_email_data['payload']['emails'][2].get('email'), 'john-smith@example.com')
                self.assertEqual(new_email_data['payload']['emails'][2].get('verified'), False)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_primary(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True

        response = self.browser.post('/primary')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                data = {
                    'email': 'johnsmith@example.com',
                    'csrf_token': sess.get_csrf_token()
                }

                response2 = client.post('/primary', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                new_email_data = json.loads(response2.data)

                self.assertEqual(new_email_data['type'], 'POST_EMAIL_PRIMARY_SUCCESS')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_primary_fail(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True

        response = self.browser.post('/primary')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            data = {
                'email': 'johnsmith2@example.com',
                'verified': True,
                'primary': True,
            }

            response2 = client.post('/primary', data=json.dumps(data),
                                    content_type=self.content_type_json)

            self.assertEqual(response2.status_code, 200)

            new_email_data = json.loads(response2.data)

            self.assertEqual(new_email_data['type'], 'POST_EMAIL_PRIMARY_FAIL')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True

        response = self.browser.post('/remove')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                data = {
                    'email': 'johnsmith2@example.com',
                    'csrf_token': sess.get_csrf_token()
                }

                response2 = client.post('/remove', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                delete_email_data = json.loads(response2.data)

                self.assertEqual(delete_email_data['type'], 'POST_EMAIL_REMOVE_SUCCESS')
                self.assertEqual(delete_email_data['payload']['emails'][0].get('email'), 'johnsmith@example.com')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_resend_code(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True

        response = self.browser.post('/resend-code')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                data = {
                    'email': 'johnsmith@example.com',
                    'csrf_token': sess.get_csrf_token()
                }

                response2 = client.post('/resend-code', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                delete_email_data = json.loads(response2.data)

                self.assertEqual(delete_email_data['type'], 'POST_EMAIL_RESEND_CODE_SUCCESS')
                self.assertEqual(delete_email_data['payload']['emails'][0].get('email'), 'johnsmith@example.com')
                self.assertEqual(delete_email_data['payload']['emails'][1].get('email'), 'johnsmith2@example.com')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_resend_code_fails(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True

        response = self.browser.post('/resend-code')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                data = {
                    'email': 'johnsmith3@example.com',
                    'csrf_token': sess.get_csrf_token()
                }

                response2 = client.post('/resend-code', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                delete_email_data = json.loads(response2.data)

                self.assertEqual(delete_email_data['type'], 'POST_EMAIL_RESEND_CODE_FAIL')

                self.assertEqual(delete_email_data['payload']['error']['form'], u'out_of_sync')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.email.verifications.get_unique_hash')
    def test_verify(self, mock_code_verification, mock_request_user_sync):
        mock_request_user_sync.return_value = False
        mock_code_verification.return_value = u'432123425'

        response = self.browser.post('/verify')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                data = {
                    'email': u'john-smith3@example.com',
                    'verified': False,
                    'primary': False,
                    'csrf_token': sess.get_csrf_token()
                }

                client.post('/new', data=json.dumps(data),
                            content_type=self.content_type_json)

                data = {
                    'email': u'john-smith3@example.com',
                    'code': u'432123425',
                    'csrf_token': sess.get_csrf_token()
                }

                response2 = client.post('/verify', data=json.dumps(data),
                                        content_type=self.content_type_json)

                verify_email_data = json.loads(response2.data)
                self.assertEqual(verify_email_data['type'], 'POST_EMAIL_VERIFY_SUCCESS')
                self.assertEqual(verify_email_data['payload']['emails'][2]['email'], u'john-smith3@example.com')
                self.assertEqual(verify_email_data['payload']['emails'][2]['verified'], True)
                self.assertEqual(verify_email_data['payload']['emails'][2]['primary'], False)
