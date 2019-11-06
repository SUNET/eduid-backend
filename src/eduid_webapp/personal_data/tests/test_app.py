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
from mock import patch

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
        app_config.update({
            'available_languages': {'en': 'English','sv': 'Svenska'},
            'msg_broker_url': 'amqp://dummy',
            'am_broker_url': 'amqp://dummy',
            'celery_config': {
                'result_backend': 'amqp',
                'task_serializer': 'json'
            },
        })
        return FlaskConfig(**app_config)

    def test_get_user(self):
        response = self.browser.get('/user')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/user')

            user_data = json.loads(response2.data)
            self.assertEqual(user_data['type'], 'GET_PERSONAL_DATA_USER_SUCCESS')
            self.assertEqual(user_data['payload']['given_name'], 'John')
            self.assertEqual(user_data['payload']['surname'], 'Smith')
            self.assertEqual(user_data['payload']['display_name'], 'John Smith')
            self.assertEqual(user_data['payload']['language'], 'en')

    def test_get_user_all_data(self):
        response = self.browser.get('/all-user-data')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/all-user-data')

            user_data = json.loads(response2.data)
            self.assertEqual(user_data['type'],
                    'GET_PERSONAL_DATA_ALL_USER_DATA_SUCCESS')
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

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_post_user(self, mock_request_user_sync):
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
                        'csrf_token': sess.get_csrf_token()
                        }
                response = client.post('/user', data=json.dumps(data),
                                       content_type=self.content_type_json)
                resp_data = json.loads(response.data)
                self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_SUCCESS')
                self.assertEqual(resp_data['payload']['surname'], 'Johnson')
                self.assertEqual(resp_data['payload']['given_name'], 'Peter')
                self.assertEqual(resp_data['payload']['display_name'], 'Peter Johnson')
                self.assertEqual(resp_data['payload']['language'], 'en')

    def test_post_user_bad_csrf(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:

                data = {
                    'given_name': 'Peter',
                    'surname': 'Johnson',
                    'display_name': 'Peter Johnson',
                    'language': 'en',
                    'csrf_token': 'bad_csrf'
                    }
                response = client.post('/user', data=json.dumps(data),
                                       content_type=self.content_type_json)
                resp_data = json.loads(response.data)
                self.assertEqual(resp_data['type'], 'POST_PERSONAL_DATA_USER_FAIL')
                self.assertEqual(resp_data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_get_user_nins(self):
        response = self.browser.get('/nins')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/nins')

            nin_data = json.loads(response2.data)
            self.assertEqual(nin_data['type'], 'GET_PERSONAL_DATA_NINS_SUCCESS')
            self.assertEqual(nin_data['payload']['nins'][1]['number'], '197801011235')
            self.assertEqual(len(nin_data['payload']['nins']), 2)
