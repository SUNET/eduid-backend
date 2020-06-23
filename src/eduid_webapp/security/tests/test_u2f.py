# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json

from mock import patch
from u2flib_server.model import DeviceRegistration, RegisteredKey

from eduid_common.api.testing import EduidAPITestCase
from eduid_userdb.credentials import U2F

from eduid_webapp.security.app import security_init_app
from eduid_webapp.security.settings.common import SecurityConfig

__author__ = 'lundberg'


class SecurityU2FTests(EduidAPITestCase):
    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, app_config):
        app_config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'msg_broker_url': 'amqp://dummy',
                'am_broker_url': 'amqp://dummy',
                'celery_config': {'result_backend': 'amqp', 'task_serializer': 'json'},
                'u2f_app_id': 'https://eduid.se/u2f-app-id.json',
                'u2f_max_allowed_tokens': 2,
                'u2f_facets': 'https://dashboard.eduid.se',
                'u2f_max_description_length': 50,
            }
        )
        return SecurityConfig(**app_config)

    def add_token_to_user(self, eppn):
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        u2f_token = U2F.from_dict(
            dict(
                version='version',
                keyhandle='keyHandle',
                app_id='appId',
                public_key='publicKey',
                attest_cert='cert',
                description='description',
                created_ts=True,
                created_by='eduid_security',
            )
        )
        user.credentials.add(u2f_token)
        self.app.central_userdb.save(user)
        return u2f_token

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
        _ = self.add_token_to_user(eppn)

        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/u2f/enroll')
            with client.session_transaction() as sess:
                self.assertIsNotNone(sess['_u2f_enroll_'])
                u2f_enroll = json.loads(sess['_u2f_enroll_'])
                self.assertEqual(u2f_enroll['appId'], 'https://eduid.se/u2f-app-id.json')
                self.assertEqual(
                    u2f_enroll['registeredKeys'],
                    [{u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'}],
                )
                self.assertIn('challenge', u2f_enroll['registerRequests'][0])
                self.assertIn('version', u2f_enroll['registerRequests'][0])

            enroll_data = json.loads(response2.data)
            self.assertEqual(enroll_data['type'], 'GET_U2F_U2F_ENROLL_SUCCESS')
            self.assertEqual(enroll_data['payload']['appId'], 'https://eduid.se/u2f-app-id.json')
            self.assertEqual(
                enroll_data['payload']['registeredKeys'],
                [{u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'}],
            )
            self.assertIn('challenge', enroll_data['payload']['registerRequests'][0])
            self.assertIn('version', enroll_data['payload']['registerRequests'][0])

    @patch('cryptography.x509.load_der_x509_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('u2flib_server.model.U2fRegisterRequest.complete')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_bind_key(self, mock_request_user_sync, mock_u2f_register_complete, mock_dump_cert, mock_load_cert):
        mock_dump_cert.return_value = b'der_cert'
        mock_load_cert.return_value = b'pem_cert'
        mock_request_user_sync.side_effect = self.request_user_sync
        mock_u2f_register_complete.return_value = (
            DeviceRegistration(
                version='mock version',
                keyHandle='mock keyhandle',
                appId='mock app id',
                publicKey='mock public key',
                transports='mock transport',
            ),
            'mock certificate',
        )

        response = self.browser.post('/u2f/bind', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            enroll_response = client.get('/u2f/enroll')
            csrf_token = json.loads(enroll_response.data)['payload']['csrf_token']

            data = {
                'csrf_token': csrf_token,
                'registrationData': 'mock registration data',
                'clientData': 'mock client data',
                'version': 'U2F_V2',
            }
            response2 = client.post('/u2f/bind', data=json.dumps(data), content_type=self.content_type_json)
            bind_data = json.loads(response2.data)
            self.assertEqual('POST_U2F_U2F_BIND_SUCCESS', bind_data['type'])
            self.assertNotEqual([], bind_data['payload']['credentials'])

    def test_sign(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        _ = self.add_token_to_user(eppn)

        response = self.browser.get('/u2f/sign')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/u2f/sign')
            with client.session_transaction() as sess:
                self.assertIsNotNone(sess['_u2f_challenge_'])
                u2f_challenge = json.loads(sess['_u2f_challenge_'])
                self.assertEqual(u2f_challenge['appId'], 'https://eduid.se/u2f-app-id.json')
                self.assertEqual(
                    u2f_challenge['registeredKeys'],
                    [{u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'}],
                )
                self.assertIn('challenge', u2f_challenge)

            enroll_data = json.loads(response2.data)
            self.assertEqual(enroll_data['type'], 'GET_U2F_U2F_SIGN_SUCCESS')
            self.assertEqual(enroll_data['payload']['appId'], 'https://eduid.se/u2f-app-id.json')
            self.assertEqual(
                enroll_data['payload']['registeredKeys'],
                [{u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'}],
            )
            self.assertIn('challenge', enroll_data['payload'])

    @patch('u2flib_server.model.U2fSignRequest.complete')
    def test_verify(self, mock_u2f_sign_complete):
        eppn = self.test_user_data['eduPersonPrincipalName']
        _ = self.add_token_to_user(eppn)
        device = RegisteredKey({u'keyHandle': u'keyHandle', u'version': u'version', u'appId': u'appId'})
        mock_u2f_sign_complete.return_value = device, 1, 0  # device, signature counter, user presence (touch)

        response = self.browser.post('/u2f/bind', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            sign_response = client.get('/u2f/sign')
            csrf_token = json.loads(sign_response.data)['payload']['csrf_token']
            data = {
                'csrf_token': csrf_token,
                'signatureData': 'mock registration data',
                'clientData': 'mock client data',
                'keyHandle': 'keyHandle',
            }
            response2 = client.post('/u2f/verify', data=json.dumps(data), content_type=self.content_type_json)
            verify_data = json.loads(response2.data)
            self.assertEqual(verify_data['type'], 'POST_U2F_U2F_VERIFY_SUCCESS')
            self.assertIsNotNone(verify_data['payload']['keyHandle'])
            self.assertIsNotNone(verify_data['payload']['counter'])
            self.assertIsNotNone(verify_data['payload']['touch'])

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_modify(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        user_token = self.add_token_to_user(eppn)

        response = self.browser.post('/u2f/modify', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            credentials_response = client.get('/credentials')
            csrf_token = json.loads(credentials_response.data)['payload']['csrf_token']
            data = {
                'csrf_token': csrf_token,
                'credential_key': user_token.key,
                'description': 'test description',
            }
            response2 = client.post('/u2f/modify', data=json.dumps(data), content_type=self.content_type_json)
            modify_data = json.loads(response2.data)
            self.assertEqual(modify_data['type'], 'POST_U2F_U2F_MODIFY_SUCCESS')
            self.assertIsNotNone(modify_data['payload']['credentials'])
            for credential in modify_data['payload']['credentials']:
                self.assertIsNotNone(credential)
                if credential['key'] == 'keyHandle':
                    self.assertEqual(credential['description'], 'test description')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        user_token = self.add_token_to_user(eppn)

        response = self.browser.post('/u2f/remove', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            credentials_response = client.get('/credentials')
            csrf_token = json.loads(credentials_response.data)['payload']['csrf_token']
            data = {
                'csrf_token': csrf_token,
                'credential_key': user_token.key,
            }
            response2 = client.post('/u2f/remove', data=json.dumps(data), content_type=self.content_type_json)
            modify_data = json.loads(response2.data)
            self.assertEqual(modify_data['type'], 'POST_U2F_U2F_REMOVE_SUCCESS')
            self.assertIsNotNone(modify_data['payload']['credentials'])
            for credential in modify_data['payload']['credentials']:
                self.assertIsNotNone(credential)
                if credential['key'] == user_token.key:
                    raise AssertionError('credential with keyhandle keyHandle should be missing')
