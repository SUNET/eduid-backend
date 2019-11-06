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

from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.phone.app import phone_init_app
from eduid_webapp.phone.settings.common import PhoneConfig


class PhoneTests(EduidAPITestCase):

    def setUp(self):
        super(PhoneTests, self).setUp(copy_user_to_private=True)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return phone_init_app('testing', config)

    def update_config(self, app_config):
        app_config.update({
            'available_languages': {'en': 'English','sv': 'Svenska'},
            'msg_broker_url': 'amqp://dummy',
            'am_broker_url': 'amqp://dummy',
            'celery_config': {
                'result_backend': 'amqp',
                'task_serializer': 'json'
            },
            'phone_verification_timeout': 7200,
            'default_country_code': '46',
            'throttle_resend_seconds': 300,
        })
        return PhoneConfig(**app_config)

    def test_get_all_phone(self):
        response = self.browser.get('/all')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/all')

            self.assertEqual(response.status_code, 302)

            phone_data = json.loads(response2.data)

            self.assertEqual('GET_PHONE_ALL_SUCCESS', phone_data['type'])
            self.assertIsNotNone(phone_data['payload']['csrf_token'])
            self.assertEqual('+34609609609', phone_data['payload']['phones'][0].get('number'))
            self.assertEqual(True, phone_data['payload']['phones'][0].get('primary'))
            self.assertEqual('+34 6096096096', phone_data['payload']['phones'][1].get('number'))
            self.assertEqual(False, phone_data['payload']['phones'][1].get('primary'))

    def test_post_phone_error_no_data(self):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302) # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.post('/new')

            self.assertEqual(response.status_code, 302)

            new_phone_data = json.loads(response2.data)
            self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_post_phone_country_code(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
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

                        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
                        self.assertEqual(u'+34670123456', new_phone_data['payload']['phones'][2].get('number'))
                        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_post_phone_no_country_code(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
                        data = {
                            'number': '0701234565',
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token()
                        }

                        response2 = client.post('/new', data=json.dumps(data),
                                                content_type=self.content_type_json)

                        self.assertEqual(response2.status_code, 200)

                        new_phone_data = json.loads(response2.data)

                        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
                        self.assertEqual(u'+46701234565', new_phone_data['payload']['phones'][2].get('number'))
                        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_post_phone_bad_csrf(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

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

                    self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])
                    self.assertEqual(['CSRF failed to validate'], new_phone_data['payload']['error']['csrf_token'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_primary(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

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

                self.assertEqual('POST_PHONE_PRIMARY_SUCCESS', new_phone_data['type'])
                self.assertEqual(True, new_phone_data['payload']['phones'][0]['verified'])
                self.assertEqual(True, new_phone_data['payload']['phones'][0]['primary'])
                self.assertEqual(u'+34609609609', new_phone_data['payload']['phones'][0]['number'])
                self.assertEqual(False, new_phone_data['payload']['phones'][1]['verified'])
                self.assertEqual(False, new_phone_data['payload']['phones'][1]['primary'])
                self.assertEqual(u'+34 6096096096', new_phone_data['payload']['phones'][1]['number'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_primary_fail(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

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

            self.assertEqual('POST_PHONE_PRIMARY_FAIL', new_phone_data['type'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

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

                self.assertEqual('POST_PHONE_REMOVE_SUCCESS', delete_phone_data['type'])
                self.assertEqual(u'+34 6096096096', delete_phone_data['payload']['phones'][0].get('number'))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove_primary_other_unverified(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post('/remove')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {
                        'number': '+34 6096096096',
                        'csrf_token': sess.get_csrf_token()
                    }

                response2 = client.post('/remove', data=json.dumps(data),
                                        content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                delete_phone_data = json.loads(response2.data)

                self.assertEqual('POST_PHONE_REMOVE_SUCCESS', delete_phone_data['type'])
                self.assertEqual(u'+34609609609', delete_phone_data['payload']['phones'][0].get('number'))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_remove_primary_other_verified(self, mock_code_verification, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = u'12345'

        response = self.browser.post('/remove')
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
                    self.assertEqual('POST_PHONE_VERIFY_SUCCESS', verify_phone_data['type'])

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

                self.assertEqual('POST_PHONE_REMOVE_SUCCESS', delete_phone_data['type'])
                self.assertEqual(u'+34 6096096096', delete_phone_data['payload']['phones'][0].get('number'))

    @patch('eduid_webapp.phone.verifications.get_short_hash')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_resend_code(self, mock_request_user_sync, mock_code_verification):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = u'5250f9a4'

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

                    self.assertEqual('POST_PHONE_RESEND_CODE_SUCCESS', phone_data['type'])
                    self.assertEqual(u'+34609609609', phone_data['payload']['phones'][0].get('number'))
                    self.assertEqual(u'+34 6096096096', phone_data['payload']['phones'][1].get('number'))

    @patch('eduid_webapp.phone.verifications.get_short_hash')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_throttle_resend_code(self, mock_request_user_sync, mock_code_verification):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = u'5250f9a4'

        response = self.browser.post('/resend-code')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator',
                           return_value=True) as send_verification_code_mock:

                    # Request a code
                    with self.app.test_request_context():
                        data = {
                            'number': '+34609609609',
                            'csrf_token': sess.get_csrf_token()
                        }

                    response2 = client.post('/resend-code', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    phone_data = json.loads(response2.data)

                    self.assertEqual('POST_PHONE_RESEND_CODE_SUCCESS', phone_data['type'])
                    self.assertEqual(u'+34609609609', phone_data['payload']['phones'][0].get('number'))
                    self.assertEqual(u'+34 6096096096', phone_data['payload']['phones'][1].get('number'))

                    # Request a new code
                    data['csrf_token'] = phone_data['payload']['csrf_token']
                    response2 = client.post('/resend-code', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    self.assertEqual(response2.status_code, 200)

                    phone_data = json.loads(response2.data)

                    self.assertEqual('POST_PHONE_RESEND_CODE_FAIL', phone_data['type'])
                    self.assertEqual(phone_data['error'], True)
                    self.assertEqual(phone_data['payload']['message'], 'still-valid-code')
                    self.assertIsNotNone(phone_data['payload']['csrf_token'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_verify(self, mock_code_verification, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
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
                    self.assertEqual('POST_PHONE_VERIFY_SUCCESS', verify_phone_data['type'])
                    self.assertEqual(u'+34609123321', verify_phone_data['payload']['phones'][2]['number'])
                    self.assertEqual(True, verify_phone_data['payload']['phones'][2]['verified'])
                    self.assertEqual(False, verify_phone_data['payload']['phones'][2]['primary'])
                    self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_verify_fail(self, mock_code_verification, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = u'12345'

        response = self.browser.post('/verify')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator',
                           return_value=True) as send_verification_code_mock:
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
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator',
                           return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
                        data = {
                            'number': u'+34609123321',
                            'code': u'wrong_code',
                            'csrf_token': sess.get_csrf_token()
                        }

                    response2 = client.post('/verify', data=json.dumps(data),
                                            content_type=self.content_type_json)

                    verify_phone_data = json.loads(response2.data)
                    self.assertEqual(verify_phone_data['type'], 'POST_PHONE_VERIFY_FAIL')
                    self.assertEqual(verify_phone_data['payload']['message'], 'phones.code_invalid_or_expired')
                    self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_post_phone_duplicated_number(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
                        data = {
                            'number': '0701234565',
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token()
                        }

                        response2 = client.post('/new', data=json.dumps(data),
                                                content_type=self.content_type_json)

                        self.assertEqual(response2.status_code, 200)

                        new_phone_data = json.loads(response2.data)

                        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
                        self.assertEqual(u'+46701234565', new_phone_data['payload']['phones'][2].get('number'))
                        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

                # Save above phone number for user in central db
                user = self.app.private_userdb.get_user_by_eppn(eppn)
                self.request_user_sync(user)

                with client.session_transaction() as sess2:
                    with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                        data2 = {
                            'number': '0701234565',
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess2.get_csrf_token()
                        }

                        response3 = client.post('/new', data=json.dumps(data2),
                                                content_type=self.content_type_json)

                        self.assertEqual(response3.status_code, 200)

                        new_phone_data2 = json.loads(response3.data)

                        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data2['type'])
                        self.assertEqual(['phone.phone_duplicated'], new_phone_data2['payload']['error'].get('number'))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_post_phone_duplicated_number_e_164(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
                        data = {
                            'number': '+46701234565',  # e164 format
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token()
                        }

                        response2 = client.post('/new', data=json.dumps(data),
                                                content_type=self.content_type_json)

                        self.assertEqual(response2.status_code, 200)

                        new_phone_data = json.loads(response2.data)

                        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
                        self.assertEqual(u'+46701234565', new_phone_data['payload']['phones'][2].get('number'))
                        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

                # Save above phone number for user in central db
                user = self.app.private_userdb.get_user_by_eppn(eppn)
                self.request_user_sync(user)

                with client.session_transaction() as sess2:
                    with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                        data2 = {
                            'number': '0701234565',  # National format
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess2.get_csrf_token()
                        }

                        response3 = client.post('/new', data=json.dumps(data2),
                                                content_type=self.content_type_json)

                        self.assertEqual(response3.status_code, 200)

                        new_phone_data2 = json.loads(response3.data)

                        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data2['type'])
                        self.assertEqual(['phone.phone_duplicated'], new_phone_data2['payload']['error'].get('number'))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_post_phone_duplicated_number_e_164_2(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
                        data = {
                            'number': '0701234565',  # National format
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token()
                        }

                        response2 = client.post('/new', data=json.dumps(data),
                                                content_type=self.content_type_json)

                        self.assertEqual(response2.status_code, 200)

                        new_phone_data = json.loads(response2.data)

                        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
                        self.assertEqual(u'+46701234565', new_phone_data['payload']['phones'][2].get('number'))
                        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

                # Save above phone number for user in central db
                user = self.app.private_userdb.get_user_by_eppn(eppn)
                self.request_user_sync(user)

                with client.session_transaction() as sess2:
                    with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                        data2 = {
                            'number': '+46701234565',  # e164 format
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess2.get_csrf_token()
                        }

                        response3 = client.post('/new', data=json.dumps(data2),
                                                content_type=self.content_type_json)

                        self.assertEqual(response3.status_code, 200)

                        new_phone_data2 = json.loads(response3.data)

                        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data2['type'])
                        self.assertEqual(['phone.phone_duplicated'], new_phone_data2['payload']['error'].get('number'))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_post_phone_bad_swedish_mobile(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
                        data = {
                            'number': '0711234565',  # National format
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token()
                        }

                        response2 = client.post('/new', data=json.dumps(data),
                                                content_type=self.content_type_json)

                        self.assertEqual(response2.status_code, 200)

                        new_phone_data = json.loads(response2.data)

                        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])
                        self.assertEqual(['phone.swedish_mobile_format'],
                                         new_phone_data['payload']['error'].get('number'))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def test_post_phone_bad_country_code(self, mock_code_verification, mock_request_user_sync):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True) as send_verification_code_mock:
                    with self.app.test_request_context():
                        data = {
                            'number': '00711234565',  # National format
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token()
                        }

                        response2 = client.post('/new', data=json.dumps(data),
                                                content_type=self.content_type_json)

                        self.assertEqual(response2.status_code, 200)

                        new_phone_data = json.loads(response2.data)

                        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])
                        self.assertEqual(['phone.e164_format'],
                                         new_phone_data['payload']['error'].get('_schema'))
