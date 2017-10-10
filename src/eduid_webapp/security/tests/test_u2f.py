# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json

from mock import patch
from u2flib_server.model import DeviceRegistration, U2fSignRequest

from eduid_userdb.u2f import U2F
from eduid_userdb.security import SecurityUser
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.security.app import security_init_app

__author__ = 'lundberg'


class SecurityTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
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
            'UF2_APP_ID': 'https://eduid.se/u2f-app-id.json',
            'U2F_MAX_ALLOWED_TOKENS': 2
        })
        return config

    def add_token_to_user(self, eppn):
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        u2f_token = U2F(version='version', keyhandle='keyHandle', app_id='appId',
                        public_key='publicKey', attest_cert='cert', description='description',
                        application='eduid_security', created_ts=True)
        user.credentials.add(u2f_token)
        self.app.central_userdb.save(user)
        return SecurityUser(data=user.to_dict())

    def test_enroll_first_key(self):
        response = self.browser.get('/u2f/enroll')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/u2f/enroll')
            with client.session_transaction() as sess:
                self.assertIsNotNone(sess['_u2f_enroll_'])
                u2f_enroll = json.loads(sess['_u2f_enroll_'])
                self.assertEqual(u2f_enroll['appId'], 'https://eduid.se/u2f-app-id.json')
                self.assertEqual(u2f_enroll['registeredKeys'], [])
                self.assertIn('challenge', u2f_enroll['registerRequests'][0])
                self.assertIn('version', u2f_enroll['registerRequests'][0])

            enroll_data = json.loads(response2.data)
            self.assertEqual(enroll_data['type'], 'GET_U2F_U2F_ENROLL_SUCCESS')
            self.assertEqual(enroll_data['payload']['appId'], 'https://eduid.se/u2f-app-id.json')
            self.assertEqual(enroll_data['payload']['registeredKeys'], [])
            self.assertIn('challenge', enroll_data['payload']['registerRequests'][0])
            self.assertIn('version', enroll_data['payload']['registerRequests'][0])

    def test_enroll_another_key(self):
        response = self.browser.get('/u2f/enroll')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        self.add_token_to_user(eppn)

        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/u2f/enroll')
            with client.session_transaction() as sess:
                self.assertIsNotNone(sess['_u2f_enroll_'])
                u2f_enroll = json.loads(sess['_u2f_enroll_'])
                self.assertEqual(u2f_enroll['appId'], 'https://eduid.se/u2f-app-id.json')
                self.assertEqual(u2f_enroll['registeredKeys'],
                                 [{u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'}])
                self.assertIn('challenge', u2f_enroll['registerRequests'][0])
                self.assertIn('version', u2f_enroll['registerRequests'][0])

            enroll_data = json.loads(response2.data)
            self.assertEqual(enroll_data['type'], 'GET_U2F_U2F_ENROLL_SUCCESS')
            self.assertEqual(enroll_data['payload']['appId'], 'https://eduid.se/u2f-app-id.json')
            self.assertEqual(enroll_data['payload']['registeredKeys'],
                             [{u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'}])
            self.assertIn('challenge', enroll_data['payload']['registerRequests'][0])
            self.assertIn('version', enroll_data['payload']['registerRequests'][0])

    @patch('u2flib_server.model.U2fRegisterRequest.complete')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_bind_key(self, mock_request_user_sync, mock_u2f_register_complete):
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_u2f_register_complete.return_value = DeviceRegistration(
            version='mock version',
            keyHandle='mock keyhandle',
            appId='mock app id',
            publicKey='mock public key',
            transports='mock transport',
        ), 'mock certificate'

        response = self.browser.post('/u2f/bind', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            enroll_response = client.get('/u2f/enroll')
            csrf_token = json.loads(enroll_response.data)['csrf_token']

            data = {
                'csrf_token': csrf_token,
                'registrationData': 'mock registration data',
                'clientData': 'mock client data',
                'version': 'U2F_V2'
            }
            response2 = client.post('/u2f/bind', data=json.dumps(data), content_type=self.content_type_json)
            bind_data = json.loads(response2.data)
            self.assertEqual(bind_data['type'], 'POST_U2F_U2F_BIND_SUCCESS')
            self.assertIsNotNone(bind_data['payload']['credentials'])

    def test_sign(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        security_user = self.add_token_to_user(eppn)


        #mock_u2f_sign_response.return_value = U2fSignRequest(
        #    version='mock version',
        #    keyHandle='mock keyhandle',
        #    appId='mock app id',
        #    publicKey='mock public key',
        #    transports='mock transport',
        #), 'mock certificate'

        response = self.browser.get('/u2f/sign')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/u2f/sign')
            with client.session_transaction() as sess:
                self.assertIsNotNone(sess['_u2f_challenge_'])
                u2f_challenge = json.loads(sess['_u2f_challenge_'])
                self.assertEqual(u2f_challenge['appId'], 'https://eduid.se/u2f-app-id.json')
                self.assertEqual(u2f_challenge['registeredKeys'],
                                 [{u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'}])
                self.assertIn('challenge', u2f_challenge)

            enroll_data = json.loads(response2.data)
            self.assertEqual(enroll_data['type'], 'GET_U2F_U2F_SIGN_SUCCESS')
            self.assertEqual(enroll_data['payload']['appId'], 'https://eduid.se/u2f-app-id.json')
            self.assertEqual(enroll_data['payload']['registeredKeys'],
                             [{u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'}])
            self.assertIn('challenge', enroll_data['payload'])

#    @patch('u2flib_server.model.U2fRegisterRequest.complete')
#    def test_verify(self, mock_u2f_register_complete):
#
#        response = self.browser.post('/u2f/bind', data={})
#        self.assertEqual(response.status_code, 302)  # Redirect to token service
#
#        mock_u2f_register_complete.return_value = DeviceRegistration(
#            version='mock version',
#            keyHandle='mock keyhandle',
#            appId='mock app id',
#            publicKey='mock public key',
#            transports='mock transport',
#        ), 'mock certificate'
#
#        eppn = self.test_user_data['eduPersonPrincipalName']
#
#        with self.session_cookie(self.browser, eppn) as client:
#            enroll_response = client.get('/u2f/verify')
#            csrf_token = json.loads(enroll_response.data)['csrf_token']
#
#            data = {
#                'csrf_token': csrf_token,
#                'registrationData': 'mock registration data',
#                'clientData': 'mock client data',
#                'version': 'U2F_V2'
#            }
#            response2 = client.post('/u2f/verify', data=json.dumps(data), content_type=self.content_type_json)
#            bind_data = json.loads(response2.data)
#            self.assertEqual(bind_data['type'], 'POST_U2F_U2F_BIND_SUCCESS')
#            self.assertIsNotNone(bind_data['payload']['credentials'])
