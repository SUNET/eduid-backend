# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
import base64
import unittest

from mock import patch
from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject
from fido2.server import Fido2Server, RelyingParty

from eduid_userdb.credentials import Webauthn, U2F
from eduid_userdb.security import SecurityUser
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.security.app import security_init_app
from eduid_webapp.security.settings.common import SecurityConfig
from eduid_webapp.security.views.webauthn import get_webauthn_server
from eduid_webapp.security.views.webauthn import urlsafe_b64decode

__author__ = 'eperez'


# CTAP1 test data

# result of calling Fido2Server.register_begin
REGISTRATION_DATA = {
    'publicKey': {'attestation': 'none',
                  'authenticatorSelection': {'requireResidentKey': False,
                                              'userVerification': 'discouraged'},
                  'challenge': b')\x03\x00S\x8b\xe1X\xbb^R\x88\x9e\xe7\x8a\x03}'
                               b's\x8d\\\x80@\xfa\x18(\xa2O\xbfN\x84\x19R\\',
                  'excludeCredentials': [],
                  'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
                  'rp': {'id': 'localhost', 'name': 'Demo server'},
                  'timeout': 30000,
                  'user': {'displayName': 'John Smith',
                              'id': b'012345678901234567890123',
                              'name': 'John'}}}


STATE = {'challenge': 'KQMAU4vhWLteUoie54oDfXONXIBA-hgook-_ToQZUlw', 'user_verification': 'discouraged'}

# Data returned by the UA in response to the above registration data using a CTAP1 key, encoded as base64url
REGISTERING_DATA = (b'onFhdHRlc3RhdGlvbk9iamVjdFjio2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5'
                    b'YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQDH4l0'
                    b'N55lhp-bfKryjw5E7q0P3Yg-nFRUBONRgkpsTOpzhhPk71udaZ-8TWurBRF6E8yBh1tzLgAFg'
                    b'CcVXO0EelAQIDJiABIVggwfFVVUARAPGhvWAt94cyLGCW2EBTMWBl70KdMPMqSBAiWCCK7GQo'
                    b'RgbMfvE_stkZN85WEQxBzXONUHkJ7cmCbLKGkG5jbGllbnREYXRhSlNPTljheyJjaGFsbGVuZ'
                    b'2UiOiJLUU1BVTR2aFdMdGVVb2llNTRvRGZYT05YSUJBLWhnb29rLV9Ub1FaVWx3IiwibmV3X2'
                    b'tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiB'
                    b'hZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4i'
                    b'OiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9')

ATTESTATION_OBJECT = (b'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjL'
                      b'HmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQDH4l0N55lhp-bfKryjw5E7q0P3Yg-'
                      b'nFRUBONRgkpsTOpzhhPk71udaZ-8TWurBRF6E8yBh1tzLgAFgCcVXO0EelAQIDJiABIVggw'
                      b'fFVVUARAPGhvWAt94cyLGCW2EBTMWBl70KdMPMqSBAiWCCK7GQoRgbMfvE_stkZN85WEQxB'
                      b'zXONUHkJ7cmCbLKGkA')

CLIENT_DATA_JSON = (b'eyJjaGFsbGVuZ2UiOiJLUU1BVTR2aFdMdGVVb2llNTRvRGZYT05YSUJBLWhnb29rLV9Ub1FaV'
                    b'Wx3IiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbn'
                    b'REYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXg'
                    b'iLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwidHlwZSI6IndlYmF1dGhuLmNy'
                    b'ZWF0ZSJ9')

CREDENTIAL_ID = ('31f8974379e65869f9b7caaf28f0e44eead0fdd883e9c545404e351824a6c4cea738613e4ef5b9'
                 'd699fbc4d6bab05117a13cc81875b732e00058027155ced047')

# CTAP2 test data

# result of calling Fido2Server.register_begin
REGISTRATION_DATA_2 = {
    'publicKey': {'attestation': 'none',
                  'authenticatorSelection': {'requireResidentKey': False,
                                              'userVerification': 'discouraged'},
                  'challenge': b"y\xe2*'\x8c\xea\xabF\xf0\xb8'k\x8c\x9ec\xd1"
                               b'ia\x1c\x9a\xd8\xfc5\xed\x0b@Q0\x9b\xe1u\r',
                  'excludeCredentials': [{'id': b'1\xf8\x97Cy\xe6Xi'
                                                b'\xf9\xb7\xca\xaf(\xf0\xe4N'
                                                b'\xea\xd0\xfd\xd8\x83\xe9\xc5E'
                                                b'@N5\x18$\xa6\xc4\xce\xa78a>'
                                                b'N\xf5\xb9\xd6\x99\xfb\xc4\xd6'
                                                b'\xba\xb0Q\x17\xa1<\xc8\x18'
                                                b'u\xb72\xe0\x00X\x02qU\xce\xd0G',
                                        'type': 'public-key'}],
                  'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
                  'rp': {'id': 'localhost', 'name': 'Demo server'},
                  'timeout': 30000,
                  'user': {'displayName': 'John Smith',
                              'id': b'012345678901234567890123',
                              'name': 'John'}}}

STATE_2 = {'challenge': 'eeIqJ4zqq0bwuCdrjJ5j0WlhHJrY_DXtC0BRMJvhdQ0', 'user_verification': 'discouraged'}

# Data returned by the UA in response to the above registration data using a CTAP2 key, encoded as base64url
REGISTERING_DATA_2 = (b'onFhdHRlc3RhdGlvbk9iamVjdFjio2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5'
                      b'YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAgAAAAAAAAAAAAAAAAAAAAAAQHutO1'
                      b'n6FunohA4v0VwCajyafSh3_X2Xwlo7MVjRqcuh4Ut8mRORX5EjZsGL0GvJ6QO8d5QJqKfHSVE'
                      b'eK0TlTIilAQIDJiABIVggTSEL0--BrS0lf87s4e-KA-Kkzkl8qlZIZsM7m6mBVD8iWCCKA78z'
                      b'zCQ9j-lHKa1pBnN5Ix-IipZePnZMKYTCTciWUW5jbGllbnREYXRhSlNPTljheyJjaGFsbGVuZ'
                      b'2UiOiJlZUlxSjR6cXEwYnd1Q2Ryako1ajBXbGhISnJZX0RYdEMwQlJNSnZoZFEwIiwibmV3X2'
                      b'tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiB'
                      b'hZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4i'
                      b'OiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9')

ATTESTATION_OBJECT_2 = (b'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjL'
                        b'HmVzzuoMdl2NBAAAAAgAAAAAAAAAAAAAAAAAAAAAAQHutO1n6FunohA4v0VwCajyafSh3_X'
                        b'2Xwlo7MVjRqcuh4Ut8mRORX5EjZsGL0GvJ6QO8d5QJqKfHSVEeK0TlTIilAQIDJiABIVggT'
                        b'SEL0--BrS0lf87s4e-KA-Kkzkl8qlZIZsM7m6mBVD8iWCCKA78zzCQ9j-lHKa1pBnN5Ix-I'
                        b'ipZePnZMKYTCTciWUQ')

CLIENT_DATA_JSON_2 = (b'eyJjaGFsbGVuZ2UiOiJlZUlxSjR6cXEwYnd1Q2Ryako1ajBXbGhISnJZX0RYdEMwQlJNSnZoZ'
                      b'FEwIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbn'
                      b'REYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXg'
                      b'iLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwidHlwZSI6IndlYmF1dGhuLmNy'
                      b'ZWF0ZSJ9')

CREDENTIAL_ID_2 = ('7bad3b59fa16e9e8840e2fd15c026a3c9a7d2877fd7d97c25a3b3158d1a9cba1e14b7c9913915'
                   'f912366c18bd06bc9e903bc779409a8a7c749511e2b44e54c88')


class SecurityWebauthnTests(EduidAPITestCase):

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return security_init_app('testing', config)

    def update_config(self, app_config):
        app_config.update({
            'available_languages': {'en': 'English', 'sv': 'Svenska'},
            'msg_broker_url': 'amqp://dummy',
            'am_broker_url': 'amqp://dummy',
            'celery_config': {
                'result_backend': 'amqp',
                'task_serializer': 'json'
            },
            'webauthn_max_allowed_tokens': 10,
            'fido2_rp_id': 'localhost'
        })
        return SecurityConfig(**app_config)

    def _add_token_to_user(self, registration_data, state):
        data = registration_data + (b'=' * (len(registration_data) % 4)) 
        data = base64.urlsafe_b64decode(data)
        data = cbor.decode(data)
        client_data = ClientData(data['clientDataJSON'])
        attestation = data['attestationObject']
        att_obj = AttestationObject(attestation)
        server = get_webauthn_server(self.app.config.fido2_rp_id)
        auth_data = server.register_complete(state, client_data, att_obj)
        cred_data = auth_data.credential_data
        cred_id = cred_data.credential_id

        credential = Webauthn(
            keyhandle = cred_id.hex(),
            credential_data = base64.urlsafe_b64encode(cred_data).decode('ascii'),
            app_id = self.app.config.fido2_rp_id,
            attest_obj = base64.b64encode(attestation).decode('ascii'),
            description = 'ctap1 token',
            application = 'test_security'
            )
        self.test_user.credentials.add(credential)
        self.app.central_userdb.save(self.test_user, check_sync=False)
        return credential

    def _add_u2f_token_to_user(self, eppn):
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        u2f_token = U2F(version='version', keyhandle='keyHandle', app_id='appId',
                        public_key='publicKey', attest_cert='cert', description='description',
                        application='eduid_security', created_ts=True)
        user.credentials.add(u2f_token)
        self.app.central_userdb.save(user)
        return u2f_token

    def _begin_register_key(self, other=None, authenticator='cross-platform', existing_legacy_token=False):
        response = self.browser.get('/webauthn/register/begin')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        if existing_legacy_token:
            self._add_u2f_token_to_user(eppn)

        if other == 'ctap1':
            user_token = self._add_token_to_user(REGISTERING_DATA, STATE)
        elif other == 'ctap2':
            user_token = self._add_token_to_user(REGISTERING_DATA_2, STATE_2)

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    data = {
                        'csrf_token': sess.get_csrf_token(),
                        'authenticator': authenticator
                        }
                response2 = client.post('/webauthn/register/begin',
                                        data=json.dumps(data),
                                        content_type=self.content_type_json)
                with client.session_transaction() as sess:
                    self.assertIsNotNone(sess['_webauthn_state_'])
                    webauthn_state = sess['_webauthn_state_']
                self.assertEqual(webauthn_state['user_verification'], 'discouraged')
                self.assertIn('challenge', webauthn_state)

            data = json.loads(response2.data)
            self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_SUCCESS')
            self.assertIn('registration_data', data['payload'])
            self.assertIn('csrf_token', data['payload'])

    def test_begin_register_first_key(self):
        self._begin_register_key()

    def test_begin_register_first_key_with_legacy_token(self):
        self._begin_register_key(existing_legacy_token=True)

    def test_begin_register_2nd_key_ater_ctap1(self):
        self._begin_register_key(other='ctap1')

    def test_begin_register_2nd_key_ater_ctap1_with_legacy_token(self):
        self._begin_register_key(other='ctap1', existing_legacy_token=True)

    def test_begin_register_2nd_key_ater_ctap2(self):
        self._begin_register_key(other='ctap2')

    def test_begin_register_2nd_key_ater_ctap2_with_legacy_token(self):
        self._begin_register_key(other='ctap2', existing_legacy_token=True)

    def test_begin_register_first_device(self):
        self._begin_register_key(authenticator='platform')

    def test_begin_register_first_device_with_legacy_token(self):
        self._begin_register_key(authenticator='platform', existing_legacy_token=True)

    def test_begin_register_2nd_device_ater_ctap1(self):
        self._begin_register_key(other='ctap1', authenticator='platform')

    def test_begin_register_2nd_device_ater_ctap1_with_legacy_token(self):
        self._begin_register_key(other='ctap1', authenticator='platform', existing_legacy_token=True)

    def test_begin_register_2nd_device_ater_ctap2(self):
        self._begin_register_key(other='ctap2', authenticator='platform')

    def test_begin_register_2nd_device_ater_ctap2_with_legacy_token(self):
        self._begin_register_key(other='ctap2', authenticator='platform', existing_legacy_token=True)

    def _finish_register_key(self, state, att, cdata, cred_id, existing_legacy_token=False):
        eppn = self.test_user_data['eduPersonPrincipalName']
        if existing_legacy_token:
            self._add_u2f_token_to_user(eppn)

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                sess['_webauthn_state_'] = state
                with self.app.test_request_context():
                    data = {
                        'csrf_token': sess.get_csrf_token(),
                        'attestationObject': att.decode('ascii'),
                        'clientDataJSON': cdata.decode('ascii'),
                        'credentialId': cred_id,
                        'description': 'dummy description'
                        }
                response2 = client.post('/webauthn/register/complete',
                                        data=json.dumps(data),
                                        content_type=self.content_type_json)
                data = json.loads(response2.data)
                self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REGISTER_COMPLETE_SUCCESS')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_finish_register_ctap1(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._finish_register_key(STATE, ATTESTATION_OBJECT, CLIENT_DATA_JSON, CREDENTIAL_ID)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_finish_register_ctap1_with_legacy_token(self, mock_request_user_sync):
        self._finish_register_key(STATE, ATTESTATION_OBJECT, CLIENT_DATA_JSON, CREDENTIAL_ID,
                                  existing_legacy_token=True)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_finish_register_ctap2(self, mock_request_user_sync):
        self._finish_register_key(STATE_2, ATTESTATION_OBJECT_2, CLIENT_DATA_JSON_2, CREDENTIAL_ID_2)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_finish_register_ctap2_with_legacy_token(self, mock_request_user_sync):
        self._finish_register_key(STATE_2, ATTESTATION_OBJECT_2, CLIENT_DATA_JSON_2, CREDENTIAL_ID_2,
                                  existing_legacy_token=True)

    def _dont_remove_last(self, reg_data, state, existing_legacy_token=False):
        eppn = self.test_user_data['eduPersonPrincipalName']

        if existing_legacy_token:
            self._add_u2f_token_to_user(eppn)

        user_token = self._add_token_to_user(reg_data, state)

        response = self.browser.post('/webauthn/remove', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            credentials_response = client.get('/credentials')
            csrf_token = json.loads(credentials_response.data)['payload']['csrf_token']
            data = {
                'csrf_token': csrf_token,
                'credential_key': user_token.key,
            }
            response2 = client.post('/webauthn/remove',
                                    data=json.dumps(data),
                                    content_type=self.content_type_json)
            modify_data = json.loads(response2.data)
            self.assertEqual(modify_data['type'], 'POST_WEBAUTHN_WEBAUTHN_REMOVE_SUCCESS')
            self.assertEqual(modify_data['payload']['message'], 'security.webauthn-noremove-last')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_dont_remove_last_ctap1(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._dont_remove_last(REGISTERING_DATA, STATE)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_dont_remove_last_ctap1_with_legacy_token(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._dont_remove_last(REGISTERING_DATA, STATE, existing_legacy_token=True)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_dont_remove_last_ctap2(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._dont_remove_last(REGISTERING_DATA_2, STATE_2)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_dont_remove_last_ctap2_with_legacy_token(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._dont_remove_last(REGISTERING_DATA_2, STATE_2, existing_legacy_token=True)

    def _remove(self, reg_data, state, reg_data2, state2, existing_legacy_token=False):
        eppn = self.test_user_data['eduPersonPrincipalName']
        if existing_legacy_token:
            self._add_u2f_token_to_user(eppn)

        user_token = self._add_token_to_user(reg_data, state)
        user_token2 = self._add_token_to_user(reg_data2, state2)

        response = self.browser.post('/webauthn/remove', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            credentials_response = client.get('/credentials')
            csrf_token = json.loads(credentials_response.data)['payload']['csrf_token']
            data = {
                'csrf_token': csrf_token,
                'credential_key': user_token.key,
            }
            response2 = client.post('/webauthn/remove',
                                    data=json.dumps(data),
                                    content_type=self.content_type_json)
            modify_data = json.loads(response2.data)
            self.assertEqual(modify_data['type'], 'POST_WEBAUTHN_WEBAUTHN_REMOVE_SUCCESS')
            self.assertIsNotNone(modify_data['payload']['credentials'])
            for credential in modify_data['payload']['credentials']:
                self.assertIsNotNone(credential)
                if credential['key'] == user_token.key:
                    raise AssertionError('credential with keyhandle keyHandle should be missing')

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove_ctap1(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._remove(REGISTERING_DATA, STATE, REGISTERING_DATA_2, STATE_2)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove_ctap1_with_legacy_token(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._remove(REGISTERING_DATA, STATE, REGISTERING_DATA_2, STATE_2, existing_legacy_token=True)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove_ctap2(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._remove(REGISTERING_DATA_2, STATE_2, REGISTERING_DATA, STATE)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove_ctap2_legacy_token(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync
        self._remove(REGISTERING_DATA_2, STATE_2, REGISTERING_DATA, STATE, existing_legacy_token=True)
