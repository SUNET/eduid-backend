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
from eduid_webapp.phone.app import phone_init_app


class PhoneTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropiate flask
        app for this test case.
        """
        return phone_init_app('testing', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English','sv': 'Svenska'},
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
        })
        return config

    def init_data(self):
        self.app.private_userdb.save(self.app.private_userdb.UserClass(data=self.test_user.to_dict()), check_sync=False)

    def test_get_all_phone(self):
        response = self.browser.get('/all')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/all')

            self.assertEqual(response.status_code, 302)

            phone_data = json.loads(response2.data)

            self.assertEqual(phone_data['type'], 'GET_PHONE_ALL_SUCCESS')
            self.assertEqual(phone_data['payload']['phones'][0].get('number'), '+34609609609')
            self.assertEqual(phone_data['payload']['phones'][0].get('primary'), True)
            self.assertEqual(phone_data['payload']['phones'][1].get('number'), '+34 6096096096')
            self.assertEqual(phone_data['payload']['phones'][1].get('primary'), False)

    def test_post_phone_error_no_data(self):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302) # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.post('/new')

            self.assertEqual(response.status_code, 302)

            new_phone_data = json.loads(response2.data)
            self.assertEqual(new_phone_data['type'], 'POST_PHONE_NEW_FAIL')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_unique_hash')
    def test_post_phone(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4-72d7-4930-b2a0-853497f0aea39'
        mock_request_user_sync.return_value = True

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:

                    data = {
                        'number': '+34670123456',
                        'verified': False,
                        'primary': False,
                        'csrf_token': sess.get_csrf_token()
                    }

                    response2 = client.post('/new', data=json.dumps(data),
                                           content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    new_phone_data = json.loads(response2.data)

                    self.assertEqual(new_phone_data['type'], 'POST_PHONE_NEW_SUCCESS')
                    self.assertEqual(new_phone_data['payload']['phones'][2].get('number'), u'+34670123456')
                    self.assertEqual(new_phone_data['payload']['phones'][2].get('verified'), False)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_unique_hash')
    def test_post_phone(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4-72d7-4930-b2a0-853497f0aea39'
        mock_request_user_sync.return_value = True

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:

                    data = {
                        'number': '+34670123456',
                        'verified': False,
                        'primary': False,
                        'csrf_token': 'bad_csrf'
                    }

                    response2 = client.post('/new', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    new_phone_data = json.loads(response2.data)

                    self.assertEqual(new_phone_data['type'], 'POST_PHONE_NEW_FAIL')
                    self.assertEqual(new_phone_data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_primary(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True

        response = self.browser.post('/primary')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {
                        'number': '+34609609609',
                        'csrf_token': sess.get_csrf_token()
                    }

                response2 = client.post('/primary', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                new_phone_data = json.loads(response2.data)

                self.assertEqual(new_phone_data['type'], 'POST_PHONE_PRIMARY_SUCCESS')
                self.assertEqual(new_phone_data['payload']['phones'][0]['verified'], True)
                self.assertEqual(new_phone_data['payload']['phones'][0]['primary'], True)
                self.assertEqual(new_phone_data['payload']['phones'][0]['number'], u'+34609609609')
                self.assertEqual(new_phone_data['payload']['phones'][1]['verified'], False)
                self.assertEqual(new_phone_data['payload']['phones'][1]['primary'], False)
                self.assertEqual(new_phone_data['payload']['phones'][1]['number'], u'+34 6096096096')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_primary_fail(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True

        response = self.browser.post('/primary')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            data = {
                'number': '+34609609609',
            }

            response2 = client.post('/primary', data=json.dumps(data),
                                    content_type=self.content_type_json)

            self.assertEqual(response2.status_code, 200)

            new_phone_data = json.loads(response2.data)

            self.assertEqual(new_phone_data['type'], 'POST_PHONE_PRIMARY_FAIL')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove(self, mock_request_user_sync):
        mock_request_user_sync.return_value = True

        response = self.browser.post('/remove')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {
                        'number': '+34609609609',
                        'csrf_token': sess.get_csrf_token()
                    }

                response2 = client.post('/remove', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                delete_phone_data = json.loads(response2.data)

                self.assertEqual(delete_phone_data['type'], 'POST_PHONE_REMOVE_SUCCESS')
                self.assertEqual(delete_phone_data['payload']['phones'][0].get('number'), u'+34 6096096096')

    @patch('eduid_webapp.phone.verifications.get_unique_hash')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_resend_code(self, mock_request_user_sync, mock_code_verification):
        mock_request_user_sync.return_value = True
        mock_code_verification.return_value = u'5250f9a4-72d7-4930-b2a0-853497f0aea9'

        response = self.browser.post('/resend-code')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:

                    with self.app.test_request_context():
                        data = {
                            'number': '+34609609609',
                            'csrf_token': sess.get_csrf_token()
                        }

                    response2 = client.post('/resend-code', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    phone_data = json.loads(response2.data)

                    self.assertEqual(phone_data['type'], 'POST_PHONE_RESEND_CODE_SUCCESS')
                    self.assertEqual(phone_data['payload']['phones'][0].get('number'), u'+34609609609')
                    self.assertEqual(phone_data['payload']['phones'][1].get('number'), u'+34 6096096096')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_unique_hash')
    def test_verify(self, mock_code_verification, mock_request_user_sync):
        mock_request_user_sync.return_value = False
        mock_code_verification.return_value = u'12345'

        response = self.browser.post('/verify')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:

                    with self.app.test_request_context():
                        data = {
                            'number': u'+34609123321',
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token()
                        }

                    client.post('/new', data=json.dumps(data),
                                content_type=self.content_type_json)

            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
                        data = {
                            'number': u'+34609123321',
                            'code': u'12345',
                            'csrf_token': sess.get_csrf_token()
                        }

                    response2 = client.post('/verify', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    verify_phone_data = json.loads(response2.data)
                    self.assertEqual(verify_phone_data['type'], 'POST_PHONE_VERIFY_SUCCESS')
                    self.assertEqual(verify_phone_data['payload']['phones'][2]['number'], u'+34609123321')
                    self.assertEqual(verify_phone_data['payload']['phones'][2]['verified'], True)
                    self.assertEqual(verify_phone_data['payload']['phones'][2]['primary'], False)
