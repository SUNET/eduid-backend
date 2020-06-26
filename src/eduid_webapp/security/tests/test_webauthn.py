# -*- coding: utf-8 -*-
from __future__ import absolute_import

import base64
import json
from typing import Any, Optional

from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_userdb.credentials import U2F, Webauthn

from eduid_webapp.security.app import security_init_app
from eduid_webapp.security.settings.common import SecurityConfig
from eduid_webapp.security.views.webauthn import get_webauthn_server

__author__ = 'eperez'


# CTAP1 test data

# result of calling Fido2Server.register_begin
REGISTRATION_DATA = {
    'publicKey': {
        'attestation': 'none',
        'authenticatorSelection': {'requireResidentKey': False, 'userVerification': 'discouraged'},
        'challenge': b')\x03\x00S\x8b\xe1X\xbb^R\x88\x9e\xe7\x8a\x03}' b's\x8d\\\x80@\xfa\x18(\xa2O\xbfN\x84\x19R\\',
        'excludeCredentials': [],
        'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
        'rp': {'id': 'localhost', 'name': 'Demo server'},
        'timeout': 30000,
        'user': {'displayName': 'John Smith', 'id': b'012345678901234567890123', 'name': 'John'},
    }
}


STATE = {'challenge': 'KQMAU4vhWLteUoie54oDfXONXIBA-hgook-_ToQZUlw', 'user_verification': 'discouraged'}

# Data returned by the UA in response to the above registration data using a CTAP1 key, encoded as base64url
REGISTERING_DATA = (
    b'onFhdHRlc3RhdGlvbk9iamVjdFjio2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5'
    b'YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQDH4l0'
    b'N55lhp-bfKryjw5E7q0P3Yg-nFRUBONRgkpsTOpzhhPk71udaZ-8TWurBRF6E8yBh1tzLgAFg'
    b'CcVXO0EelAQIDJiABIVggwfFVVUARAPGhvWAt94cyLGCW2EBTMWBl70KdMPMqSBAiWCCK7GQo'
    b'RgbMfvE_stkZN85WEQxBzXONUHkJ7cmCbLKGkG5jbGllbnREYXRhSlNPTljheyJjaGFsbGVuZ'
    b'2UiOiJLUU1BVTR2aFdMdGVVb2llNTRvRGZYT05YSUJBLWhnb29rLV9Ub1FaVWx3IiwibmV3X2'
    b'tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiB'
    b'hZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4i'
    b'OiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'
)

ATTESTATION_OBJECT = (
    b'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjL'
    b'HmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQDH4l0N55lhp-bfKryjw5E7q0P3Yg-'
    b'nFRUBONRgkpsTOpzhhPk71udaZ-8TWurBRF6E8yBh1tzLgAFgCcVXO0EelAQIDJiABIVggw'
    b'fFVVUARAPGhvWAt94cyLGCW2EBTMWBl70KdMPMqSBAiWCCK7GQoRgbMfvE_stkZN85WEQxB'
    b'zXONUHkJ7cmCbLKGkA'
)

CLIENT_DATA_JSON = (
    b'eyJjaGFsbGVuZ2UiOiJLUU1BVTR2aFdMdGVVb2llNTRvRGZYT05YSUJBLWhnb29rLV9Ub1FaV'
    b'Wx3IiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbn'
    b'REYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXg'
    b'iLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwidHlwZSI6IndlYmF1dGhuLmNy'
    b'ZWF0ZSJ9'
)

CREDENTIAL_ID = (
    '31f8974379e65869f9b7caaf28f0e44eead0fdd883e9c545404e351824a6c4cea738613e4ef5b9'
    'd699fbc4d6bab05117a13cc81875b732e00058027155ced047'
)

# CTAP2 test data

# result of calling Fido2Server.register_begin
REGISTRATION_DATA_2 = {
    'publicKey': {
        'attestation': 'none',
        'authenticatorSelection': {'requireResidentKey': False, 'userVerification': 'discouraged'},
        'challenge': b"y\xe2*'\x8c\xea\xabF\xf0\xb8'k\x8c\x9ec\xd1" b'ia\x1c\x9a\xd8\xfc5\xed\x0b@Q0\x9b\xe1u\r',
        'excludeCredentials': [
            {
                'id': b'1\xf8\x97Cy\xe6Xi'
                b'\xf9\xb7\xca\xaf(\xf0\xe4N'
                b'\xea\xd0\xfd\xd8\x83\xe9\xc5E'
                b'@N5\x18$\xa6\xc4\xce\xa78a>'
                b'N\xf5\xb9\xd6\x99\xfb\xc4\xd6'
                b'\xba\xb0Q\x17\xa1<\xc8\x18'
                b'u\xb72\xe0\x00X\x02qU\xce\xd0G',
                'type': 'public-key',
            }
        ],
        'pubKeyCredParams': [{'alg': -7, 'type': 'public-key'}],
        'rp': {'id': 'localhost', 'name': 'Demo server'},
        'timeout': 30000,
        'user': {'displayName': 'John Smith', 'id': b'012345678901234567890123', 'name': 'John'},
    }
}

STATE_2 = {'challenge': 'eeIqJ4zqq0bwuCdrjJ5j0WlhHJrY_DXtC0BRMJvhdQ0', 'user_verification': 'discouraged'}

# Data returned by the UA in response to the above registration data using a CTAP2 key, encoded as base64url
REGISTERING_DATA_2 = (
    b'onFhdHRlc3RhdGlvbk9iamVjdFjio2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5'
    b'YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAgAAAAAAAAAAAAAAAAAAAAAAQHutO1'
    b'n6FunohA4v0VwCajyafSh3_X2Xwlo7MVjRqcuh4Ut8mRORX5EjZsGL0GvJ6QO8d5QJqKfHSVE'
    b'eK0TlTIilAQIDJiABIVggTSEL0--BrS0lf87s4e-KA-Kkzkl8qlZIZsM7m6mBVD8iWCCKA78z'
    b'zCQ9j-lHKa1pBnN5Ix-IipZePnZMKYTCTciWUW5jbGllbnREYXRhSlNPTljheyJjaGFsbGVuZ'
    b'2UiOiJlZUlxSjR6cXEwYnd1Q2Ryako1ajBXbGhISnJZX0RYdEMwQlJNSnZoZFEwIiwibmV3X2'
    b'tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiB'
    b'hZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4i'
    b'OiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'
)

ATTESTATION_OBJECT_2 = (
    b'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjL'
    b'HmVzzuoMdl2NBAAAAAgAAAAAAAAAAAAAAAAAAAAAAQHutO1n6FunohA4v0VwCajyafSh3_X'
    b'2Xwlo7MVjRqcuh4Ut8mRORX5EjZsGL0GvJ6QO8d5QJqKfHSVEeK0TlTIilAQIDJiABIVggT'
    b'SEL0--BrS0lf87s4e-KA-Kkzkl8qlZIZsM7m6mBVD8iWCCKA78zzCQ9j-lHKa1pBnN5Ix-I'
    b'ipZePnZMKYTCTciWUQ'
)

CLIENT_DATA_JSON_2 = (
    b'eyJjaGFsbGVuZ2UiOiJlZUlxSjR6cXEwYnd1Q2Ryako1ajBXbGhISnJZX0RYdEMwQlJNSnZoZ'
    b'FEwIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbn'
    b'REYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXg'
    b'iLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo1MDAwIiwidHlwZSI6IndlYmF1dGhuLmNy'
    b'ZWF0ZSJ9'
)

CREDENTIAL_ID_2 = (
    '7bad3b59fa16e9e8840e2fd15c026a3c9a7d2877fd7d97c25a3b3158d1a9cba1e14b7c9913915'
    'f912366c18bd06bc9e903bc779409a8a7c749511e2b44e54c88'
)


class SecurityWebauthnTests(EduidAPITestCase):
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
                'webauthn_max_allowed_tokens': 10,
                'fido2_rp_id': 'localhost',
            }
        )
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

        credential = Webauthn.from_dict(
            dict(
                keyhandle=cred_id.hex(),
                credential_data=base64.urlsafe_b64encode(cred_data).decode('ascii'),
                app_id=self.app.config.fido2_rp_id,
                attest_obj=base64.b64encode(attestation).decode('ascii'),
                description='ctap1 token',
                created_by='test_security',
            )
        )
        self.test_user.credentials.add(credential)
        self.app.central_userdb.save(self.test_user, check_sync=False)
        return credential

    def _add_u2f_token_to_user(self, eppn):
        user = self.app.central_userdb.get_user_by_eppn(eppn)
        u2f_token = U2F.from_dict(
            dict(
                version='version',
                keyhandle='keyHandle',
                app_id='appId',
                public_key='publicKey',
                attest_cert='cert',
                description='description',
                created_by='eduid_security',
                created_ts=True,
            )
        )
        user.credentials.add(u2f_token)
        self.app.central_userdb.save(user)
        return u2f_token

    def _check_session_state(self, client):
        with client.session_transaction() as sess:
            self.assertIsNotNone(sess['_webauthn_state_'])
            webauthn_state = sess['_webauthn_state_']
        self.assertEqual(webauthn_state['user_verification'], 'discouraged')
        self.assertIn('challenge', webauthn_state)

    def _check_registration_begun(self, data):
        self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_SUCCESS')
        self.assertIn('registration_data', data['payload'])
        self.assertIn('csrf_token', data['payload'])

    def _check_registration_complete(self, data):
        self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REGISTER_COMPLETE_SUCCESS')
        self.assertTrue(len(data['payload']['credentials']) > 0)
        self.assertEqual(data['payload']['message'], 'security.webauthn_register_success')

    def _check_last(self, data):
        self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REMOVE_SUCCESS')
        self.assertEqual(data['payload']['message'], 'security.webauthn-noremove-last')

    def _check_removal(self, data, user_token):
        self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REMOVE_SUCCESS')
        self.assertIsNotNone(data['payload']['credentials'])
        for credential in data['payload']['credentials']:
            self.assertIsNotNone(credential)
            self.assertNotEqual(credential['key'], user_token.key)

    # parameterized test methods

    def _begin_register_key(
        self,
        other: Optional[str] = None,
        authenticator: str = 'cross-platform',
        existing_legacy_token: bool = False,
        csrf: Optional[str] = None,
        check_session: bool = True,
    ):
        """
        Start process to register a webauthn token for the test user,
        possibly adding U2F or webauthn credentials before.

        :param other: to control the credential (ctap1 or ctap2) added to the account.
        :param authenticator: which authenticator to use (platform|cross-platform)
        :param existing_legacy_token: whether to add a legacy U2F credential to the test user.
        :param csrf: to control the CSRF token to send
        :param check_session: whether to check the registration state in the session
        """
        response = self.browser.get('/webauthn/register/begin')
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        eppn = self.test_user_data['eduPersonPrincipalName']

        if existing_legacy_token:
            self._add_u2f_token_to_user(eppn)

        if other == 'ctap1':
            self._add_token_to_user(REGISTERING_DATA, STATE)
        elif other == 'ctap2':
            self._add_token_to_user(REGISTERING_DATA_2, STATE_2)

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                with self.app.test_request_context():
                    if csrf is not None:
                        csrf_token = csrf
                    else:
                        csrf_token = sess.get_csrf_token()
                    data = {'csrf_token': csrf_token, 'authenticator': authenticator}
                response2 = client.post(
                    '/webauthn/register/begin', data=json.dumps(data), content_type=self.content_type_json
                )
                if check_session:
                    self._check_session_state(client)

            return json.loads(response2.data)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _finish_register_key(
        self,
        mock_request_user_sync: Any,
        state: dict,
        att: bytes,
        cdata: bytes,
        cred_id: bytes,
        existing_legacy_token: bool = False,
        csrf: Optional[str] = None,
    ):
        """
        Finish registering a webauthn token.

        :param state: mock the webauthn registration state kept in the session
        :param att: attestation object, to attest to the provenance of the authenticator and the data it emits
        :param cdata: client data passed to the authenticator by the client
        :param cred_id: credential ID
        :param existing_legacy_token: whether to add a legacy U2F credential to the test user.
        :param csrf: to control the CSRF token to send
        """
        mock_request_user_sync.side_effect = self.request_user_sync
        eppn = self.test_user_data['eduPersonPrincipalName']
        if existing_legacy_token:
            self._add_u2f_token_to_user(eppn)

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction() as sess:
                sess['_webauthn_state_'] = state
                with self.app.test_request_context():
                    if csrf is not None:
                        csrf_token = csrf
                    else:
                        csrf_token = sess.get_csrf_token()
                    data = {
                        'csrf_token': csrf_token,
                        'attestationObject': att.decode('ascii'),
                        'clientDataJSON': cdata.decode('ascii'),
                        'credentialId': cred_id,
                        'description': 'dummy description',
                    }
                response2 = client.post(
                    '/webauthn/register/complete', data=json.dumps(data), content_type=self.content_type_json
                )
                return json.loads(response2.data)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _dont_remove_last(
        self,
        mock_request_user_sync: Any,
        reg_data: bytes,
        state: dict,
        existing_legacy_token: bool = False,
        csrf: Optional[str] = None,
    ):
        """
        Send a request to remove the only webauthn credential from the test user - which should fail.

        :param reg_data: registration data as would be produced by a browser.
        :param state: registration state kept in the session
        :param existing_legacy_token: whether to add a legacy U2F credential to the test user.
        :param csrf: to control the CSRF token to send
        """
        eppn = self.test_user_data['eduPersonPrincipalName']

        if existing_legacy_token:
            self._add_u2f_token_to_user(eppn)

        user_token = self._add_token_to_user(reg_data, state)

        response = self.browser.post('/webauthn/remove', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            credentials_response = client.get('/credentials')
            csrf_token = json.loads(credentials_response.data)['payload']['csrf_token']
            if csrf is not None:
                csrf_token = csrf
            else:
                csrf_token = json.loads(credentials_response.data)['payload']['csrf_token']
            data = {
                'csrf_token': csrf_token,
                'credential_key': user_token.key,
            }
            response2 = client.post('/webauthn/remove', data=json.dumps(data), content_type=self.content_type_json)
            return json.loads(response2.data)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def _remove(
        self,
        mock_request_user_sync: Any,
        reg_data: bytes,
        state: dict,
        reg_data2: bytes,
        state2: dict,
        existing_legacy_token: bool = False,
        csrf: Optional[str] = None,
    ):
        """
        Send a POST request to remove a webauthn credential from the test user.
        Before sending the request, add 2 webauthn credentials (and possibly a legacy u2f credential) to the test user.

        :param reg_data: registration data as would be produced by a browser.
        :param state: registration state kept in the session
        :param reg_data2: registration data as would be produced by a browser (for the 2nd webauthn credential)
        :param state2: registration state kept in the session (for the 2nd webauthn credential)
        :param existing_legacy_token: whether to add a legacy U2F credential to the test user.
        :param csrf: to control the CSRF token to send
        """
        eppn = self.test_user_data['eduPersonPrincipalName']
        if existing_legacy_token:
            self._add_u2f_token_to_user(eppn)

        user_token = self._add_token_to_user(reg_data, state)
        self._add_token_to_user(reg_data2, state2)

        response = self.browser.post('/webauthn/remove', data={})
        self.assertEqual(response.status_code, 302)  # Redirect to token service

        with self.session_cookie(self.browser, eppn) as client:
            credentials_response = client.get('/credentials')
            if csrf is not None:
                csrf_token = csrf
            else:
                csrf_token = json.loads(credentials_response.data)['payload']['csrf_token']
            data = {
                'csrf_token': csrf_token,
                'credential_key': user_token.key,
            }
            response2 = client.post('/webauthn/remove', data=json.dumps(data), content_type=self.content_type_json)
            return (user_token, json.loads(response2.data))

    # actual tests

    def test_begin_register_first_key(self):
        data = self._begin_register_key()
        self._check_registration_begun(data)

    def test_begin_register_first_key_with_legacy_token(self):
        data = self._begin_register_key(existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_2nd_key_ater_ctap1(self):
        data = self._begin_register_key(other='ctap1')
        self._check_registration_begun(data)

    def test_begin_register_2nd_key_ater_ctap1_with_legacy_token(self):
        data = self._begin_register_key(other='ctap1', existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_2nd_key_ater_ctap2(self):
        data = self._begin_register_key(other='ctap2')
        self._check_registration_begun(data)

    def test_begin_register_2nd_key_ater_ctap2_with_legacy_token(self):
        data = self._begin_register_key(other='ctap2', existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_first_device(self):
        data = self._begin_register_key(authenticator='platform')
        self._check_registration_begun(data)

    def test_begin_register_first_device_with_legacy_token(self):
        data = self._begin_register_key(authenticator='platform', existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_2nd_device_ater_ctap1(self):
        data = self._begin_register_key(other='ctap1', authenticator='platform')
        self._check_registration_begun(data)

    def test_begin_register_2nd_device_ater_ctap1_with_legacy_token(self):
        data = self._begin_register_key(other='ctap1', authenticator='platform', existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_2nd_device_ater_ctap2(self):
        data = self._begin_register_key(other='ctap2', authenticator='platform')
        self._check_registration_begun(data)

    def test_begin_register_2nd_device_ater_ctap2_with_legacy_token(self):
        data = self._begin_register_key(other='ctap2', authenticator='platform', existing_legacy_token=True)
        self._check_registration_begun(data)

    def test_begin_register_wrong_csrf_token(self):
        data = self._begin_register_key(csrf='wrong-token', check_session=False)
        self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REGISTER_BEGIN_FAIL')
        self.assertEqual(data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_finish_register_ctap1(self):
        data = self._finish_register_key(
            state=STATE, att=ATTESTATION_OBJECT, cdata=CLIENT_DATA_JSON, cred_id=CREDENTIAL_ID
        )
        self._check_registration_complete(data)

    def test_finish_register_ctap1_with_legacy_token(self):
        data = self._finish_register_key(
            state=STATE,
            att=ATTESTATION_OBJECT,
            cdata=CLIENT_DATA_JSON,
            cred_id=CREDENTIAL_ID,
            existing_legacy_token=True,
        )
        self._check_registration_complete(data)

    def test_finish_register_ctap2(self):
        data = self._finish_register_key(
            state=STATE_2, att=ATTESTATION_OBJECT_2, cdata=CLIENT_DATA_JSON_2, cred_id=CREDENTIAL_ID_2
        )
        self._check_registration_complete(data)

    def test_finish_register_ctap2_with_legacy_token(self):
        data = self._finish_register_key(
            state=STATE_2,
            att=ATTESTATION_OBJECT_2,
            cdata=CLIENT_DATA_JSON_2,
            cred_id=CREDENTIAL_ID_2,
            existing_legacy_token=True,
        )
        self._check_registration_complete(data)

    def test_finish_register_wrong_csrf(self):
        data = self._finish_register_key(
            state=STATE, att=ATTESTATION_OBJECT, cdata=CLIENT_DATA_JSON, cred_id=CREDENTIAL_ID, csrf='wrong-token'
        )
        self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REGISTER_COMPLETE_FAIL')
        self.assertEqual(data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_dont_remove_last_ctap1(self):
        data = self._dont_remove_last(reg_data=REGISTERING_DATA, state=STATE)
        self._check_last(data)

    def test_dont_remove_last_ctap1_with_legacy_token(self):
        data = self._dont_remove_last(reg_data=REGISTERING_DATA, state=STATE, existing_legacy_token=True)
        self._check_last(data)

    def test_dont_remove_last_ctap2(self):
        data = self._dont_remove_last(reg_data=REGISTERING_DATA_2, state=STATE_2)
        self._check_last(data)

    def test_dont_remove_last_ctap2_with_legacy_token(self):
        data = self._dont_remove_last(reg_data=REGISTERING_DATA_2, state=STATE_2, existing_legacy_token=True)
        self._check_last(data)

    def test_dont_remove_last_wrong_csrf(self):
        data = self._dont_remove_last(reg_data=REGISTERING_DATA, state=STATE, csrf='wrong-token')
        self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REMOVE_FAIL')
        self.assertEqual(data['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_remove_ctap1(self):
        user_token, data = self._remove(
            reg_data=REGISTERING_DATA, state=STATE, reg_data2=REGISTERING_DATA_2, state2=STATE_2
        )
        self._check_removal(data, user_token)

    def test_remove_ctap1_with_legacy_token(self):
        user_token, data = self._remove(
            reg_data=REGISTERING_DATA,
            state=STATE,
            reg_data2=REGISTERING_DATA_2,
            state2=STATE_2,
            existing_legacy_token=True,
        )
        self._check_removal(data, user_token)

    def test_remove_ctap2(self):
        user_token, data = self._remove(
            reg_data=REGISTERING_DATA_2, state=STATE_2, reg_data2=REGISTERING_DATA, state2=STATE
        )
        self._check_removal(data, user_token)

    def test_remove_ctap2_legacy_token(self):
        user_token, data = self._remove(
            reg_data=REGISTERING_DATA_2,
            state=STATE_2,
            reg_data2=REGISTERING_DATA,
            state2=STATE,
            existing_legacy_token=True,
        )
        self._check_removal(data, user_token)

    def test_remove_wrong_csrf(self):
        user_token, data = self._remove(
            reg_data=REGISTERING_DATA, state=STATE, reg_data2=REGISTERING_DATA_2, state2=STATE_2, csrf='wrong-csrf'
        )
        self.assertEqual(data['type'], 'POST_WEBAUTHN_WEBAUTHN_REMOVE_FAIL')
        self.assertEqual(data['payload']['error']['csrf_token'], ['CSRF failed to validate'])
