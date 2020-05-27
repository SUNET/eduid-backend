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
from typing import Any, Optional
from urllib.parse import quote_plus

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
        app_config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'msg_broker_url': 'amqp://dummy',
                'am_broker_url': 'amqp://dummy',
                'celery_config': {'result_backend': 'amqp', 'task_serializer': 'json'},
                'phone_verification_timeout': 7200,
                'default_country_code': '46',
                'throttle_resend_seconds': 300,
            }
        )
        return PhoneConfig(**app_config)

    # parameterized test methods

    def _get_all_phone(self, eppn: Optional[str] = None):
        """
        GET all phone data for some user

        :param eppn: eppn for the user
        """
        response = self.browser.get('/all')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = eppn or self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/all')

            return json.loads(response2.data)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def _post_phone(
        self,
        mock_code_verification: Any,
        mock_request_user_sync: Any,
        mod_data: Optional[dict] = None,
        send_data: bool = True,
    ):
        """
        POST phone data to add a new phone number to the test user

        :param mod_data: to control what data is POSTed
        :param send_data: whether to POST any data at all
        """
        mock_code_verification.return_value = u'5250f9a4'
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):
                    with self.app.test_request_context():
                        data = {
                            'number': '+34670123456',
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token(),
                        }
                        if mod_data:
                            data.update(mod_data)

                        if send_data:
                            return client.post('/new', data=json.dumps(data), content_type=self.content_type_json)

                        return client.post('/new')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _post_primary(self, mock_request_user_sync: Any, mod_data: Optional[dict] = None):
        """
        Set phone number as the primary number for the test user

        :param mod_data: to control what data is POSTed
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post('/primary')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {'number': '+34609609609', 'csrf_token': sess.get_csrf_token()}
                    if mod_data:
                        data.update(mod_data)

                return client.post('/primary', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _remove(self, mock_request_user_sync: Any, mod_data: Optional[dict] = None):
        """
        Remove phone number from the test user

        :param mod_data: to control what data is POSTed
        """
        mock_request_user_sync.side_effect = self.request_user_sync

        response = self.browser.post('/remove')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {'number': '+34609609609', 'csrf_token': sess.get_csrf_token()}
                    if mod_data:
                        data.update(mod_data)

                return client.post('/remove', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_webapp.phone.verifications.get_short_hash')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _resend_code(self, mock_request_user_sync: Any, mock_code_verification: Any, mod_data: Optional[dict] = None):
        """
        Send a POST request to trigger re-sending a verification code for an unverified phone number in the test user.

        :param mod_data: to control the data to be POSTed
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_code_verification.return_value = u'5250f9a4'

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):

                    with self.app.test_request_context():
                        data = {'number': '+34609609609', 'csrf_token': sess.get_csrf_token()}
                        if mod_data:
                            data.update(mod_data)

                    return client.post('/resend-code', data=json.dumps(data), content_type=self.content_type_json)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    @patch('eduid_webapp.phone.verifications.get_short_hash')
    def _get_code_backdoor(
        self,
        mock_code_verification: Any,
        mock_request_user_sync: Any,
        mod_data: Optional[dict] = None,
        phone: str = '+34670123456',
        code: str = '5250f9a4',
    ):
        """
        POST phone data to generate a verification state,
        and try to get the generated code through the backdoor

        :param mod_data: to control what data is POSTed
        :param phone: the phone to use
        :param code: mock verification code
        """
        mock_code_verification.return_value = code
        mock_request_user_sync.side_effect = self.request_user_sync

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):
                    with self.app.test_request_context():
                        data = {
                            'number': phone,
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token(),
                        }
                        if mod_data:
                            data.update(mod_data)

                        client.post('/new', data=json.dumps(data), content_type=self.content_type_json)

                        client.set_cookie(
                            'localhost', key=self.app.config.magic_cookie_name, value=self.app.config.magic_cookie
                        )

                        phone = quote_plus(phone)
                        eppn = quote_plus(eppn)

                        return client.get(f'/get-code?phone={phone}&eppn={eppn}')

    # actual tests

    def test_get_all_phone(self):
        phone_data = self._get_all_phone()

        self.assertEqual('GET_PHONE_ALL_SUCCESS', phone_data['type'])
        self.assertIsNotNone(phone_data['payload']['csrf_token'])
        self.assertEqual('+34609609609', phone_data['payload']['phones'][0].get('number'))
        self.assertEqual(True, phone_data['payload']['phones'][0].get('primary'))
        self.assertEqual('+34 6096096096', phone_data['payload']['phones'][1].get('number'))
        self.assertEqual(False, phone_data['payload']['phones'][1].get('primary'))

    def test_post_phone_error_no_data(self):
        response = self._post_phone(send_data=False)
        new_phone_data = json.loads(response.data)
        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])

    def test_post_phone_country_code(self):
        response = self.browser.post('/new')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        response = self._post_phone()

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
        self.assertEqual(u'+34670123456', new_phone_data['payload']['phones'][2].get('number'))
        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

    def test_post_phone_no_country_code(self):
        data = {'number': '0701234565'}
        response = self._post_phone(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
        self.assertEqual(u'+46701234565', new_phone_data['payload']['phones'][2].get('number'))
        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

    def test_post_phone_wrong_csrf(self):
        data = {'csrf_token': 'wrong-token'}
        response = self._post_phone(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])
        self.assertEqual(['CSRF failed to validate'], new_phone_data['payload']['error']['csrf_token'])

    def test_post_phone_invalid(self):
        data = {'number': '0'}
        response = self._post_phone(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])
        self.assertEqual(['phone.phone_format'], new_phone_data['payload']['error']['number'])

    def test_post_phone_as_verified(self):
        data = {'verified': True}
        response = self._post_phone(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
        self.assertEqual(u'+34670123456', new_phone_data['payload']['phones'][2].get('number'))
        self.assertFalse(new_phone_data['payload']['phones'][2].get('verified'))
        self.assertFalse(new_phone_data['payload']['phones'][2].get('primary'))

    def test_post_phone_as_primary(self):
        data = {'primary': True}
        response = self._post_phone(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
        self.assertEqual(u'+34670123456', new_phone_data['payload']['phones'][2].get('number'))
        self.assertFalse(new_phone_data['payload']['phones'][2].get('verified'))
        self.assertFalse(new_phone_data['payload']['phones'][2].get('primary'))

    def test_post_phone_bad_swedish_mobile(self):
        data = {'number': '0711234565'}
        response = self._post_phone(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])
        self.assertEqual(['phone.swedish_mobile_format'], new_phone_data['payload']['error'].get('number'))

    def test_post_phone_bad_country_code(self):
        data = {'number': '00711234565'}
        response = self._post_phone(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data['type'])
        self.assertEqual(['phone.e164_format'], new_phone_data['payload']['error'].get('_schema'))

    def test_post_primary(self):
        response = self._post_primary()

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_PRIMARY_SUCCESS', new_phone_data['type'])
        self.assertEqual(True, new_phone_data['payload']['phones'][0]['verified'])
        self.assertEqual(True, new_phone_data['payload']['phones'][0]['primary'])
        self.assertEqual(u'+34609609609', new_phone_data['payload']['phones'][0]['number'])
        self.assertEqual(False, new_phone_data['payload']['phones'][1]['verified'])
        self.assertEqual(False, new_phone_data['payload']['phones'][1]['primary'])
        self.assertEqual(u'+34 6096096096', new_phone_data['payload']['phones'][1]['number'])

    def test_post_primary_no_csrf(self):
        data = {'csrf_token': ''}
        response = self._post_primary(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_PRIMARY_FAIL', new_phone_data['type'])
        self.assertEqual(['CSRF failed to validate'], new_phone_data['payload']['error']['csrf_token'])

    def test_post_primary_unknown(self):
        data = {'number': '+66666666666'}
        response = self._post_primary(mod_data=data)

        self.assertEqual(response.status_code, 200)
        new_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_PRIMARY_FAIL', new_phone_data['type'])
        self.assertEqual('user-out-of-sync', new_phone_data['payload']['message'])

    def test_remove(self):
        response = self._remove()

        self.assertEqual(response.status_code, 200)

        delete_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_REMOVE_SUCCESS', delete_phone_data['type'])
        self.assertEqual(u'+34 6096096096', delete_phone_data['payload']['phones'][0].get('number'))

    def test_remove_primary_other_unverified(self):
        data = {'number': '+34 6096096096'}
        response = self._remove(mod_data=data)

        self.assertEqual(response.status_code, 200)

        delete_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_REMOVE_SUCCESS', delete_phone_data['type'])
        self.assertEqual(u'+34609609609', delete_phone_data['payload']['phones'][0].get('number'))

    def test_remove_no_csrf(self):
        data = {'csrf_token': ''}
        response = self._remove(mod_data=data)

        self.assertEqual(response.status_code, 200)

        delete_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_REMOVE_FAIL', delete_phone_data['type'])
        self.assertEqual(['CSRF failed to validate'], delete_phone_data['payload']['error']['csrf_token'])

    def test_remove_unknown(self):
        data = {'number': '+33333333333'}
        response = self._remove(mod_data=data)

        self.assertEqual(response.status_code, 200)

        delete_phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_REMOVE_FAIL', delete_phone_data['type'])
        self.assertEqual('phones.unknown_phone', delete_phone_data['payload']['message'])

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
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):

                    with self.app.test_request_context():
                        data = {
                            'number': u'+34609123321',
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token(),
                        }

                    client.post('/new', data=json.dumps(data), content_type=self.content_type_json)
            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):
                    with self.app.test_request_context():
                        data = {'number': u'+34609123321', 'code': u'12345', 'csrf_token': sess.get_csrf_token()}

                    response2 = client.post('/verify', data=json.dumps(data), content_type=self.content_type_json)
                    verify_phone_data = json.loads(response2.data)
                    self.assertEqual('POST_PHONE_VERIFY_SUCCESS', verify_phone_data['type'])

            with client.session_transaction() as sess:

                with self.app.test_request_context():
                    data = {'number': '+34609609609', 'csrf_token': sess.get_csrf_token()}

                response2 = client.post('/remove', data=json.dumps(data), content_type=self.content_type_json)

                self.assertEqual(response2.status_code, 200)

                delete_phone_data = json.loads(response2.data)

                self.assertEqual('POST_PHONE_REMOVE_SUCCESS', delete_phone_data['type'])
                self.assertEqual(u'+34 6096096096', delete_phone_data['payload']['phones'][0].get('number'))

    def test_resend_code(self):
        response = self.browser.post('/resend-code')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        response = self._resend_code()

        self.assertEqual(response.status_code, 200)
        phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_RESEND_CODE_SUCCESS', phone_data['type'])
        self.assertEqual(u'+34609609609', phone_data['payload']['phones'][0].get('number'))
        self.assertEqual(u'+34 6096096096', phone_data['payload']['phones'][1].get('number'))

    def test_resend_code_no_csrf(self):
        data = {'csrf_token': 'wrong-token'}
        response = self._resend_code(mod_data=data)

        self.assertEqual(response.status_code, 200)
        phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_RESEND_CODE_FAIL', phone_data['type'])
        self.assertEqual(['CSRF failed to validate'], phone_data['payload']['error']['csrf_token'])

    def test_resend_code_unknown(self):
        data = {'number': '+66666666666'}
        response = self._resend_code(mod_data=data)

        self.assertEqual(response.status_code, 200)
        phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_RESEND_CODE_FAIL', phone_data['type'])
        self.assertEqual('user-out-of-sync', phone_data['payload']['message'])

    def test_resend_code_throttle(self):
        response = self._resend_code()

        self.assertEqual(response.status_code, 200)
        phone_data = json.loads(response.data)

        self.assertEqual('POST_PHONE_RESEND_CODE_SUCCESS', phone_data['type'])
        self.assertEqual(u'+34609609609', phone_data['payload']['phones'][0].get('number'))
        self.assertEqual(u'+34 6096096096', phone_data['payload']['phones'][1].get('number'))

        response = self._resend_code()

        self.assertEqual(response.status_code, 200)
        phone_data = json.loads(response.data)

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
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):

                    with self.app.test_request_context():
                        data = {
                            'number': u'+34609123321',
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token(),
                        }

                    client.post('/new', data=json.dumps(data), content_type=self.content_type_json)

            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):
                    with self.app.test_request_context():
                        data = {'number': u'+34609123321', 'code': u'12345', 'csrf_token': sess.get_csrf_token()}

                    response2 = client.post('/verify', data=json.dumps(data), content_type=self.content_type_json)

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
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):
                    with self.app.test_request_context():
                        data = {
                            'number': u'+34609123321',
                            'verified': False,
                            'primary': False,
                            'csrf_token': sess.get_csrf_token(),
                        }

                    client.post('/new', data=json.dumps(data), content_type=self.content_type_json)

            with client.session_transaction() as sess:
                with patch('eduid_webapp.phone.verifications.current_app.msg_relay.phone_validator', return_value=True):
                    with self.app.test_request_context():
                        data = {'number': u'+34609123321', 'code': u'wrong_code', 'csrf_token': sess.get_csrf_token()}

                    response2 = client.post('/verify', data=json.dumps(data), content_type=self.content_type_json)

                    verify_phone_data = json.loads(response2.data)
                    self.assertEqual(verify_phone_data['type'], 'POST_PHONE_VERIFY_FAIL')
                    self.assertEqual(verify_phone_data['payload']['message'], 'phones.code_invalid_or_expired')
                    self.assertEqual(self.app.proofing_log.db_count(), 0)

    def test_post_phone_duplicated_number(self):
        data = {'number': '0701234565'}
        response1 = self._post_phone(mod_data=data)

        self.assertEqual(response1.status_code, 200)
        new_phone_data = json.loads(response1.data)

        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
        self.assertEqual(u'+46701234565', new_phone_data['payload']['phones'][2].get('number'))
        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

        eppn = self.test_user_data['eduPersonPrincipalName']

        # Save above phone number for user in central db
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.request_user_sync(user)

        response2 = self._post_phone(mod_data=data)

        self.assertEqual(response2.status_code, 200)

        new_phone_data2 = json.loads(response2.data)

        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data2['type'])
        self.assertEqual(['phone.phone_duplicated'], new_phone_data2['payload']['error'].get('number'))

    def test_post_phone_duplicated_number_e_164(self):
        data = {'number': '+46701234565'}  # e164 format
        response1 = self._post_phone(mod_data=data)

        self.assertEqual(response1.status_code, 200)
        new_phone_data = json.loads(response1.data)

        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
        self.assertEqual('+46701234565', new_phone_data['payload']['phones'][2].get('number'))
        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

        eppn = self.test_user_data['eduPersonPrincipalName']

        # Save above phone number for user in central db
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.request_user_sync(user)

        data = {'number': '0701234565'}  # National format
        response2 = self._post_phone(mod_data=data)

        self.assertEqual(response2.status_code, 200)

        new_phone_data2 = json.loads(response2.data)

        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data2['type'])
        self.assertEqual(['phone.phone_duplicated'], new_phone_data2['payload']['error'].get('number'))

    def test_post_phone_duplicated_number_e_164_2(self):
        data = {'number': '0701234565'}  # e164 format
        response1 = self._post_phone(mod_data=data)

        self.assertEqual(response1.status_code, 200)
        new_phone_data = json.loads(response1.data)

        self.assertEqual('POST_PHONE_NEW_SUCCESS', new_phone_data['type'])
        self.assertEqual('+46701234565', new_phone_data['payload']['phones'][2].get('number'))
        self.assertEqual(False, new_phone_data['payload']['phones'][2].get('verified'))

        eppn = self.test_user_data['eduPersonPrincipalName']

        # Save above phone number for user in central db
        user = self.app.private_userdb.get_user_by_eppn(eppn)
        self.request_user_sync(user)

        data = {'number': '+46701234565'}  # National format
        response2 = self._post_phone(mod_data=data)

        self.assertEqual(response2.status_code, 200)

        new_phone_data2 = json.loads(response2.data)

        self.assertEqual('POST_PHONE_NEW_FAIL', new_phone_data2['type'])
        self.assertEqual(['phone.phone_duplicated'], new_phone_data2['payload']['error'].get('number'))

    def test_get_code_backdoor(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        code = '0123456'
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data, code.encode('ascii'))

    def test_get_code_no_backdoor_in_pro(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'pro'

        code = '0123456'
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured1(self):
        self.app.config.magic_cookie = 'magic-cookie'
        self.app.config.magic_cookie_name = ''
        self.app.config.environment = 'dev'

        code = '0123456'
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 400)

    def test_get_code_no_backdoor_misconfigured2(self):
        self.app.config.magic_cookie = ''
        self.app.config.magic_cookie_name = 'magic'
        self.app.config.environment = 'dev'

        code = '0123456'
        resp = self._get_code_backdoor(code=code)

        self.assertEqual(resp.status_code, 400)
