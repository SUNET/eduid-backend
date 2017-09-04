# -*- coding: utf-8 -*-

from __future__ import absolute_import

import time
import json
import jose
from collections import OrderedDict
from mock import patch

from eduid_userdb.data_samples import NEW_UNVERIFIED_USER_EXAMPLE
from eduid_userdb.user import User
from eduid_userdb.nin import Nin
from eduid_userdb.locked_identity import LockedIdentityNin
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.oidc_proofing.app import init_oidc_proofing_app
from eduid_webapp.oidc_proofing.helpers import create_proofing_state, handle_freja_eid_userinfo, handle_seleg_userinfo

__author__ = 'lundberg'


class OidcProofingTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):

        self.test_user_eppn = 'hubba-bubba'
        self.test_user_nin = '200001023456'
        self.mock_address = OrderedDict([
            (u'Name', OrderedDict([
                (u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'),
                (u'Surname', u'Testsson')])),
            (u'OfficialAddress', OrderedDict([(u'Address2', u'\xd6RGATAN 79 LGH 10'),
                                              (u'PostalCode', u'12345'),
                                              (u'City', u'LANDET')]))
        ])

        self.oidc_provider_config = {
            'authorization_endpoint': 'https://example.com/op/authentication',
            'claims_parameter_supported': True,
            'grant_types_supported': [
                'authorization_code',
                'implicit'
            ],
            'id_token_signing_alg_values_supported': [
                'RS256'
            ],
            'issuer': 'https://example.com/op/',
            'jwks_uri': 'https://example.com/op/jwks',
            'response_modes_supported': [
                'query',
                'fragment'
            ],
            'response_types_supported': [
                'code',
                'code id_token',
                'code token',
                'code id_token token'
            ],
            'scopes_supported': [
                'openid'
            ],
            'subject_types_supported': [
                'pairwise'
            ],
            'token_endpoint': 'https://example.com/op/token',
            'token_endpoint_auth_methods_supported': [
                'client_secret_basic'
            ],
            'userinfo_endpoint': 'https://example.com/op/userinfo'
        }

        class MockResponse(object):
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text

        self.oidc_provider_config_response = MockResponse(200, json.dumps(self.oidc_provider_config))

        super(OidcProofingTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        with patch('oic.oic.Client.http_request') as mock_response:
            mock_response.return_value = self.oidc_provider_config_response
            return init_oidc_proofing_app('testing', config)

    def init_data(self):
        """
        Called from the parent class, so we can extend data initialized.
        """
        test_user = User(data=NEW_UNVERIFIED_USER_EXAMPLE)  # eppn hubba-baar
        self.app.central_userdb.save(test_user, check_sync=False)

    def update_config(self, config):
        config.update({
            'MSG_BROKER_URL': 'amqp://dummy',
            'AM_BROKER_URL': 'amqp://dummy',
            'CELERY_CONFIG': {
                'CELERY_RESULT_BACKEND': 'amqp',
                'CELERY_TASK_SERIALIZER': 'json'
            },
            'PROVIDER_CONFIGURATION_INFO': {
                'issuer': 'https://example.com/op/'
            },
            'CLIENT_REGISTRATION_INFO': {
                'client_id': 'test_client',
                'client_secret': 'secret'
            },
            'FREJA_JWS_ALGORITHM': 'HS256',
            'FREJA_JWS_KEY_ID': '0',
            'FREJA_JWK_SECRET': '499602d2',  # in hex
            'FREJA_IARP': 'TESTRP',
            'FREJA_EXPIRE_TIME_HOURS': 336,
            'FREJA_RESPONSE_PROTOCOL': '1.0'
        })
        return config

    def tearDown(self):
        super(OidcProofingTests, self).tearDown()
        with self.app.app_context():
            self.app.proofing_statedb._drop_whole_collection()
            self.app.proofing_userdb._drop_whole_collection()
            self.app.proofing_log._drop_whole_collection()
            self.app.central_userdb._drop_whole_collection()

    def test_authenticate(self):
        response = self.browser.get('/proofing')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/proofing')
        self.assertEqual(response.status_code, 200)  # Authenticated request

    def test_get_empty_seleg_state(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

    def test_get_empty_freja_state(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

    def test_get_freja_state(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        proofing_state = create_proofing_state(user, self.test_user_nin)
        self.app.proofing_statedb.save(proofing_state)
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')
        jwk = {'k': self.app.config['FREJA_JWK_SECRET'].decode('hex')}
        jwt = response['payload']['iaRequestData']
        request_data = jose.verify(jose.deserialize_compact(jwt), jwk, alg=self.app.config['FREJA_JWS_ALGORITHM'])
        expected = {
            'iarp': 'TESTRP',
            'opaque': '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token}),
            'proto': u'1.0'
        }
        self.assertIn('exp', request_data.claims)
        self.assertEqual(request_data.claims['iarp'], expected['iarp'])
        self.assertEqual(request_data.claims['opaque'], expected['opaque'])
        self.assertEqual(request_data.claims['proto'], expected['proto'])

    def test_get_seleg_state_bad_csrf(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': 'bad_csrf'}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_FAIL')
        self.assertEqual(response['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    def test_get_freja_state_bad_csrf(self):
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': 'bad_csrf'}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_FAIL')
        self.assertEqual(response['payload']['error']['csrf_token'], ['CSRF failed to validate'])

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_seleg_flow(self, mock_oidc_call, mock_get_postal_address, mock_request_user_sync):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.return_value = True
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        # No actual oidc flow tested here
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        userinfo = {
            'identity': self.test_user_nin,
        }
        with self.app.app_context():
            handle_seleg_userinfo(user, proofing_state, userinfo)
        user = self.app.proofing_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_freja_flow(self, mock_oidc_call, mock_get_postal_address, mock_request_user_sync):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.return_value = True
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        # No actual oidc flow tested here
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        userinfo = {
            'results': {
                'freja_eid': {
                    'vetting_time': time.time(),
                    'ref': '1234.5678.9012.3456',
                    'opaque': '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token}),
                    'country': 'SE',
                    'ssn': self.test_user_nin,
                }
            }
        }
        with self.app.app_context():
            handle_freja_eid_userinfo(user, proofing_state, userinfo)
        user = self.app.proofing_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_freja_flow_previously_added_nin(self, mock_oidc_call, mock_get_postal_address, mock_request_user_sync):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.return_value = True
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        not_verified_nin = Nin(number=self.test_user_nin, application='test', verified=False, primary=False)
        user.nins.add(not_verified_nin)
        self.app.central_userdb.save(user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        # No actual oidc flow tested here
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        userinfo = {
            'results': {
                'freja_eid': {
                    'vetting_time': time.time(),
                    'ref': '1234.5678.9012.3456',
                    'opaque': '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token}),
                    'country': 'SE',
                    'ssn': self.test_user_nin,
                }
            }
        }
        with self.app.app_context():
            handle_freja_eid_userinfo(user, proofing_state, userinfo)
        user = self.app.proofing_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, not_verified_nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_seleg_locked_identity(self, mock_oidc_call, mock_request_user_sync):
        mock_oidc_call.return_value = True
        mock_request_user_sync.return_value = True
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        # User with no locked_identity
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        # User with locked_identity and correct nin
        user.locked_identity.add(LockedIdentityNin(number=self.test_user_nin, created_by='test', created_ts=True))
        self.app.central_userdb.save(user, check_sync=False)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        # User with locked_identity and incorrect nin
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': '200102031234', 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_FAIL')

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_freja_locked_identity(self, mock_oidc_call, mock_request_user_sync):
        mock_oidc_call.return_value = True
        mock_request_user_sync.return_value = True
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        user.locked_identity.add(LockedIdentityNin(number=self.test_user_nin, created_by='test', created_ts=True))
        self.app.central_userdb.save(user, check_sync=False)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': '200102031234', 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_FAIL')
