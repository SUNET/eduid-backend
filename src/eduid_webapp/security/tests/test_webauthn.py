# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
import base64
import unittest

from mock import patch
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject

from eduid_userdb.credentials import Webauthn
from eduid_userdb.security import SecurityUser
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.security.app import security_init_app
from eduid_webapp.security.views.webauthn import get_webauthn_server
from eduid_webapp.security.views.webauthn import urlsafe_b64decode

__author__ = 'eperez'


# This test data is urlsafe b64 encoded, as it would be sent by the UA to the server to
# complete registration of a token.

TEST_ATTESTATION = ("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjExoTb59PepEtaoOaf9D9NR21Ub"
                    "_INOOK_T7nl1ndsHRRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQL9b0eYGCW0QQQspGdJ"
                    "vbwZwi4X1ByfcEFvowYSfQeZJlN1l1zPMm2Lmch5Oot_ksu2n6-xGXi_d5HI6FQJF_"
                    "v2lAQIDJiABIVggUQvIq8UKi_UxUGWSZwXwxmdBRc_AWVhGRYOP87JiFJIiWCCfdz4O"
                    "1JDNj9-4LtB-eVrwH5KX_ucBKW4-JzhOVX6rsQ")

TEST_CREDENTIAL_ID = ("v1vR5gYJbRBBCykZ0m9vBnCLhfUHJ9wQW-jBhJ9B5kmU3WXXM8ybYuZyHk6i3-Sy7"
                      "afr7EZeL93kcjoVAkX-_Q")

TEST_CLIENT_DATA = ("eyJjaGFsbGVuZ2UiOiJxbEF2WjFDSmFNcjZMTWNFaENfRXpjTXF6dkh6YzU2OVQ2ME01"
                    "LXQwTHNBIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFy"
                    "ZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dv"
                    "by5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL2Rhc2hib2FyZC5lZHVpZC5sb2Nh"
                    "bC5lbWVyZ3lhLmluZm8iLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0")

TEST_STATE = {'challenge': 'qlAvZ1CJaMr6LMcEhC_EzcMqzvHzc569T60M5-t0LsA',
              'user_verification': 'preferred'}


class SecurityWebauthnTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, config):
        config.update({
            'AVAILABLE_LANGUAGES': {'en': 'English', 'sv': 'Svenska'},
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
            'WEBAUTHN_MAX_ALLOWED_TOKENS': 10,
            'FIDO2_RP_ID': 'localhost'
        })
        return config

    def add_token_to_user(self, eppn):
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        att_obj = AttestationObject(urlsafe_b64decode(TEST_ATTESTATION))
        cdata_obj = ClientData(urlsafe_b64decode(TEST_CLIENT_DATA))
        server = get_webauthn_server(self.app.config['FIDO2_RP_ID'])
        auth_data = server.register_complete(TEST_STATE, cdata_obj, att_obj)
        cred_data = auth_data.credential_data

        token = Webauthn(keyhandle=TEST_CREDENTIAL_ID,
                         credential_data=base64.urlsafe_b64encode(cred_data).decode('ascii'),
                         app_id=self.app.config['FIDO2_RP_ID'],
                         attest_obj=base64.b64encode(attestation_object.encode('utf-8')).decode('ascii'),
                         description='description',
                         application='security',
                         created_ts=True)
        user.credentials.add(token)
        self.app.central_userdb.save(user)
        return token

    def test_register_first_key(self):
        response = self.browser.get('/webauthn/register/begin')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/webauthn/register/begin')
            with client.session_transaction() as sess:
                self.assertIsNotNone(sess['_webauthn_state_'])
                webauthn_state = sess['_webauthn_state_']
                self.assertEqual(webauthn_state['user_verification'], 'preferred')
                self.assertIn('challenge', webauthn_state)

            data = json.loads(response2.data)
            self.assertEqual(data['type'], 'GET_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_SUCCESS')
            self.assertIn('registration_data', data['payload'])
            self.assertIn('csrf_token', data['payload'])

    def test_enroll_another_key(self):
        response = self.browser.get('/webauthn/register/begin')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']
        user_token = self.add_token_to_user(eppn)

        with self.session_cookie(self.browser, eppn) as client:
            response2 = client.get('/webauthn/register/begin')
            with client.session_transaction() as sess:
                self.assertIsNotNone(sess['_webauthn_state_'])
                webauthn_state = sess['_webauthn_state_']
                self.assertEqual(webauthn_state['user_verification'], 'preferred')
                self.assertIn('challenge', webauthn_state)

            data = json.loads(response2.data)
            self.assertEqual(data['type'], 'GET_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_SUCCESS')
            self.assertIn('registration_data', data['payload'])
            self.assertIn('csrf_token', data['payload'])

    @unittest.skip("Not working yet")
    @patch('cryptography.x509.load_der_x509_certificate')
    @patch('OpenSSL.crypto.dump_certificate')
    @patch('u2flib_server.model.U2fRegisterRequest.complete')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_bind_key(self, mock_request_user_sync, mock_u2f_register_complete, mock_dump_cert, mock_load_cert):
        mock_dump_cert.return_value = b'der_cert'
        mock_load_cert.return_value = b'pem_cert'
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
            csrf_token = json.loads(enroll_response.data)['payload']['csrf_token']

            data = {
                'csrf_token': csrf_token,
                'registrationData': 'mock registration data',
                'clientData': 'mock client data',
                'version': 'U2F_V2'
            }
            response2 = client.post('/u2f/bind', data=json.dumps(data), content_type=self.content_type_json)
            bind_data = json.loads(response2.data)
            self.assertEqual(bind_data['type'], 'POST_U2F_U2F_BIND_SUCCESS')
            self.assertNotEqual(bind_data['payload']['credentials'], [])

    @unittest.skip("Not working yet")
    def test_sign(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        user_token = self.add_token_to_user(eppn)

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

    @unittest.skip("Not working yet")
    @patch('u2flib_server.model.U2fSignRequest.complete')
    def test_verify(self, mock_u2f_sign_complete):
        eppn = self.test_user_data['eduPersonPrincipalName']
        user_token = self.add_token_to_user(eppn)
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
                'keyHandle': 'keyHandle'
            }
            response2 = client.post('/u2f/verify', data=json.dumps(data), content_type=self.content_type_json)
            verify_data = json.loads(response2.data)
            self.assertEqual(verify_data['type'], 'POST_U2F_U2F_VERIFY_SUCCESS')
            self.assertIsNotNone(verify_data['payload']['keyHandle'])
            self.assertIsNotNone(verify_data['payload']['counter'])
            self.assertIsNotNone(verify_data['payload']['touch'])

    @unittest.skip("Not working yet")
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

    @unittest.skip("Not working yet")
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
