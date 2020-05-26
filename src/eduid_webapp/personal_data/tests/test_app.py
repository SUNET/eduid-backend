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
#
import json
from typing import Any, Optional

from mock import patch

from eduid_common.api.exceptions import ApiException
from eduid_common.api.testing import EduidAPITestCase
from eduid_common.config.base import FlaskConfig

from eduid_webapp.personal_data.app import pd_init_app


class PersonalDataTests(EduidAPITestCase):
    def setUp(self):
        super(PersonalDataTests, self).setUp(copy_user_to_private=True)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return pd_init_app('testing', config)

    def update_config(self, app_config):
        app_config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'msg_broker_url': 'amqp://dummy',
                'am_broker_url': 'amqp://dummy',
                'celery_config': {'result_backend': 'amqp', 'task_serializer': 'json'},
            }
        )
        return FlaskConfig(**app_config)

    # parameterized test methods

    def _get_user(self, eppn: Optional[str] = None):
        """
        Send a GET request to get the personal data of a user

        :param eppn: the eppn of the user
        """
        response = self.browser.get('/user')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = eppn or self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/user')

            return json.loads(response2.data)

    def _get_user_all_data(self, eppn: Optional[str] = None):
        """
        Send a GET request to get all the data of a user

        :param eppn: the eppn of the user
        """
        response = self.browser.get('/all-user-data')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = eppn or self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/all-user-data')

            return json.loads(response2.data)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _post_user(self, mock_request_user_sync: Any, mod_data: Optional[dict] = None):
        """
        POST personal data for some user

        :param eppn: the eppn of the user
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'given_name': 'Peter',
                        'surname': 'Johnson',
                        'display_name': 'Peter Johnson',
                        'language': 'en',
                        'csrf_token': sess.get_csrf_token(),
                    }
                    if mod_data:
                        data.update(mod_data)
                response = client.post('/user', data=json.dumps(data), content_type=self.content_type_json)
                return json.loads(response.data)

    def _get_user_nins(self, eppn: Optional[str] = None):
        """
        GET a list of all the nins of some user

        :param eppn: the eppn of the user
        """
        response = self.browser.get('/nins')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = eppn or self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/nins')

            return json.loads(response2.data)

    # actual test methods

    def test_get_user(self):
        user_data = self._get_user()
        self.assertEqual(user_data['type'], 'GET_PERSONAL_DATA_USER_SUCCESS')
        self.assertEqual(user_data['payload']['given_name'], 'John')
        self.assertEqual(user_data['payload']['surname'], 'Smith')
        self.assertEqual(user_data['payload']['display_name'], 'John Smith')
        self.assertEqual(user_data['payload']['language'], 'en')
        # Check that unwanted data is not serialized
        self.assertIsNotNone(self.test_user.to_dict().get('passwords'))
        self.assertIsNone(user_data['payload'].get('passwords'))

    def test_get_unknown_user(self):
        with self.assertRaises(ApiException):
            self._get_user(eppn='fooo-fooo')

    def test_get_user_all_data(self):
        user_data = self._get_user_all_data()
        self.assertEqual(user_data['type'], 'GET_PERSONAL_DATA_ALL_USER_DATA_SUCCESS')
        self.assertEqual(user_data['payload']['given_name'], 'John')
        self.assertEqual(user_data['payload']['surname'], 'Smith')
        self.assertEqual(user_data['payload']['display_name'], 'John Smith')
        self.assertEqual(user_data['payload']['language'], 'en')
        phones = user_data['payload']['phones']
        self.assertEqual(len(phones), 2)
        self.assertEqual(phones[0]['number'], u'+34609609609')
        self.assertTrue(phones[0]['verified'])
        nins = user_data['payload']['nins']
        self.assertEqual(len(nins), 2)
        self.assertEqual(nins[0]['number'], u'197801011234')
        self.assertTrue(nins[0]['verified'])
        emails = user_data['payload']['emails']
        self.assertEqual(len(emails), 2)
        self.assertEqual(emails[0]['email'], u'johnsmith@example.com')
        self.assertTrue(emails[0]['verified'])

        # Check that unwanted data is not serialized
        self.assertIsNotNone(self.test_user.to_dict().get('passwords'))
        self.assertIsNone(user_data['payload'].get('passwords'))

    def test_get_unknown_user_all_data(self):
        with self.assertRaises(ApiException):
            self._get_user_all_data(eppn='fooo-fooo')

    def test_post_user(self):
        resp_data = self._post_user()
        self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_SUCCESS')
        self.assertEqual(resp_data['payload']['surname'], 'Johnson')
        self.assertEqual(resp_data['payload']['given_name'], 'Peter')
        self.assertEqual(resp_data['payload']['display_name'], 'Peter Johnson')
        self.assertEqual(resp_data['payload']['language'], 'en')

    def test_post_user_bad_csrf(self):
        resp_data = self._post_user(mod_data={'csrf_token': 'wrong-token'})
        self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_FAIL')
        self.assertEqual(resp_data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_post_user_no_given_name(self):
        resp_data = self._post_user(mod_data={'given_name': ''})
        self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_FAIL')
        self.assertEqual(resp_data['payload']['error']['given_name'], ['pdata.field_required'])

    def test_post_user_no_surname(self):
        resp_data = self._post_user(mod_data={'surname': ''})
        self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_FAIL')
        self.assertEqual(resp_data['payload']['error']['surname'], ['pdata.field_required'])

    def test_post_user_no_display_name(self):
        resp_data = self._post_user(mod_data={'display_name': ''})
        self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_FAIL')
        self.assertEqual(resp_data['payload']['error']['display_name'], ['pdata.field_required'])

    def test_post_user_no_language(self):
        resp_data = self._post_user(mod_data={'language': ''})
        self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_FAIL')
        self.assertEqual(resp_data['payload']['error']['language'], ["Language '' is not available"])

    def test_post_user_unknown_language(self):
        resp_data = self._post_user(mod_data={'language': 'es'})
        self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_FAIL')
        self.assertEqual(resp_data['payload']['error']['language'], ["Language 'es' is not available"])

    def test_get_user_nins(self):
        nin_data = self._get_user_nins()
        self.assertEqual(nin_data['type'], 'GET_PERSONAL_DATA_NINS_SUCCESS')
        self.assertEqual(nin_data['payload']['nins'][1]['number'], '197801011235')
        self.assertEqual(len(nin_data['payload']['nins']), 2)
