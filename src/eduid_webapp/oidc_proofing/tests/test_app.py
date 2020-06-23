# -*- coding: utf-8 -*-

from __future__ import absolute_import

import binascii
import json
import time
from collections import OrderedDict

from jose import jws as jose
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_userdb.exceptions import DocumentDoesNotExist
from eduid_userdb.locked_identity import LockedIdentityNin
from eduid_userdb.nin import Nin

from eduid_webapp.oidc_proofing.app import init_oidc_proofing_app
from eduid_webapp.oidc_proofing.helpers import create_proofing_state, handle_freja_eid_userinfo
from eduid_webapp.oidc_proofing.settings.common import OIDCProofingConfig

__author__ = 'lundberg'


class OidcProofingTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.test_user_eppn = 'hubba-baar'
        self.test_user_nin = '200001023456'
        self.test_user_wrong_nin = '190001021234'

        self.mock_address = OrderedDict(
            [
                (
                    u'Name',
                    OrderedDict(
                        [(u'GivenNameMarking', u'20'), (u'GivenName', u'Testaren Test'), (u'Surname', u'Testsson')]
                    ),
                ),
                (
                    u'OfficialAddress',
                    OrderedDict(
                        [(u'Address2', u'\xd6RGATAN 79 LGH 10'), (u'PostalCode', u'12345'), (u'City', u'LANDET')]
                    ),
                ),
            ]
        )

        self.oidc_provider_config = {
            'authorization_endpoint': 'https://example.com/op/authentication',
            'claims_parameter_supported': True,
            'grant_types_supported': ['authorization_code', 'implicit'],
            'id_token_signing_alg_values_supported': ['RS256'],
            'issuer': 'https://example.com/op/',
            'jwks_uri': 'https://example.com/op/jwks',
            'response_modes_supported': ['query', 'fragment'],
            'response_types_supported': ['code', 'code id_token', 'code token', 'code id_token token'],
            'scopes_supported': ['openid'],
            'subject_types_supported': ['pairwise'],
            'token_endpoint': 'https://example.com/op/token',
            'token_endpoint_auth_methods_supported': ['client_secret_basic'],
            'userinfo_endpoint': 'https://example.com/op/userinfo',
        }

        class MockResponse(object):
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text

        self.oidc_provider_config_response = MockResponse(200, json.dumps(self.oidc_provider_config))

        super(OidcProofingTests, self).setUp(users=['hubba-baar'])

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        with patch('oic.oic.Client.http_request') as mock_response:
            mock_response.return_value = self.oidc_provider_config_response
            return init_oidc_proofing_app('testing', config)

    def update_config(self, app_config):
        app_config.update(
            {
                'msg_broker_url': 'amqp://dummy',
                'am_broker_url': 'amqp://dummy',
                'celery_config': {'result_backend': 'amqp', 'task_serializer': 'json'},
                'provider_configuration_info': {'issuer': 'https://example.com/op/'},
                'client_registration_info': {'client_id': 'test_client', 'client_secret': 'secret'},
                'userinfo_endpoint_method': 'POST',
                'freja_jws_algorithm': 'HS256',
                'freja_jws_key_id': '0',
                'freja_jwk_secret': '499602d2',  # in hex
                'freja_iarp': 'TESTRP',
                'freja_expire_time_hours': 336,
                'freja_response_protocol': '1.0',
                'seleg_expire_time_hours': 336,
            }
        )
        return OIDCProofingConfig(**app_config)

    @patch('oic.oic.Client.parse_response')
    @patch('oic.oic.Client.do_user_info_request')
    @patch('oic.oic.Client.do_access_token_request')
    def mock_authorization_response(
        self, qrdata, proofing_state, userinfo, mock_token_request, mock_userinfo_request, mock_auth_response
    ):
        mock_auth_response.return_value = {
            'id_token': 'id_token',
            'code': 'code',
            'state': proofing_state.state,
        }
        mock_token_request.return_value = {'id_token': {'nonce': qrdata['nonce'], 'sub': 'sub'}}
        userinfo['sub'] = 'sub'
        mock_userinfo_request.return_value = userinfo
        headers = {'Authorization': 'Bearer {}'.format(qrdata['token'])}
        return self.browser.get(
            '/authorization-response?id_token=id_token&state={}'.format(proofing_state.state), headers=headers
        )

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
        jwk = binascii.unhexlify(self.app.config.freja_jwk_secret)
        jwt = response['payload']['iaRequestData'].encode('ascii')
        request_data = jose.verify(jwt, [jwk], self.app.config.freja_jws_algorithm)
        expected = {
            'iarp': 'TESTRP',
            'opaque': '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token}),
            'proto': u'1.0',
        }
        claims = json.loads(request_data.decode('ascii'))
        self.assertIn('exp', claims)
        self.assertEqual(claims['iarp'], expected['iarp'])
        self.assertEqual(claims['opaque'], expected['opaque'])
        self.assertEqual(claims['proto'], expected['proto'])

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
    def test_seleg_flow(self, mock_request_user_sync, mock_get_postal_address, mock_oidc_call):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        # Fake callback from OP
        qrdata = json.loads(response['payload']['qr_code'][1:])
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        userinfo = {
            'identity': self.test_user_nin,
            'metadata': {
                'score': 100,
                'opaque': '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token}),
                'ra_app': 'App id for vetting app',
            },
        }
        self.mock_authorization_response(qrdata, proofing_state, userinfo)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_common.api.mail_relay.MailRelay.sendmail')
    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_seleg_flow_low_score(self, mock_request_user_sync, mock_get_postal_address, mock_oidc_call, mock_sendmail):
        mock_sendmail.return_value = True
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        # Fake callback from OP
        qrdata = json.loads(response['payload']['qr_code'][1:])
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        userinfo = {
            'identity': self.test_user_nin,
            'metadata': {
                'score': 0,
                'opaque': '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token}),
                'ra_app': 'App id for vetting app',
            },
        }
        self.mock_authorization_response(qrdata, proofing_state, userinfo)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.count, 1)
        self.assertEqual(user.nins.verified.count, 0)
        self.assertEqual(self.app.proofing_log.db_count(), 0)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_seleg_flow_previously_added_nin(self, mock_request_user_sync, mock_get_postal_address, mock_oidc_call):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        not_verified_nin = Nin.from_dict(
            dict(number=self.test_user_nin, created_by='test', verified=False, primary=False)
        )
        user.nins.add(not_verified_nin)
        self.app.central_userdb.save(user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        # Fake callback from OP
        qrdata = json.loads(response['payload']['qr_code'][1:])
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        userinfo = {
            'identity': self.test_user_nin,
            'metadata': {
                'score': 100,
                'opaque': '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token}),
                'ra_app': 'App id for vetting app',
            },
        }
        self.mock_authorization_response(qrdata, proofing_state, userinfo)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, not_verified_nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_seleg_flow_previously_added_wrong_nin(
        self, mock_request_user_sync, mock_get_postal_address, mock_oidc_call
    ):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        not_verified_nin = Nin.from_dict(
            dict(number=self.test_user_wrong_nin, created_by='test', verified=False, primary=False)
        )
        user.nins.add(not_verified_nin)
        self.app.central_userdb.save(user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_wrong_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        # Fake callback from OP
        qrdata = json.loads(response['payload']['qr_code'][1:])
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        userinfo = {
            'identity': self.test_user_nin,
            'metadata': {
                'score': 100,
                'opaque': '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token}),
                'ra_app': 'App id for vetting app',
            },
        }
        self.mock_authorization_response(qrdata, proofing_state, userinfo)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_freja_flow(self, mock_request_user_sync, mock_get_postal_address, mock_oidc_call):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

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
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_freja_flow_previously_added_nin(self, mock_request_user_sync, mock_get_postal_address, mock_oidc_call):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        not_verified_nin = Nin.from_dict(
            dict(number=self.test_user_nin, created_by='test', verified=False, primary=False)
        )
        user.nins.add(not_verified_nin)
        self.app.central_userdb.save(user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

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
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, not_verified_nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_freja_flow_previously_added_wrong_nin(
        self, mock_request_user_sync, mock_get_postal_address, mock_oidc_call
    ):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        not_verified_nin = Nin.from_dict(
            dict(number=self.test_user_wrong_nin, created_by='test', verified=False, primary=False)
        )
        user.nins.add(not_verified_nin)
        self.app.central_userdb.save(user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_wrong_nin, 'csrf_token': csrf_token}
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
        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.nins.primary.number, self.test_user_nin)
        self.assertEqual(user.nins.primary.created_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.verified_by, proofing_state.nin.created_by)
        self.assertEqual(user.nins.primary.is_verified, True)
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.msg.MsgRelay.get_postal_address')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_freja_flow_expired_state(self, mock_request_user_sync, mock_get_postal_address, mock_oidc_call):
        mock_oidc_call.return_value = True
        mock_get_postal_address.return_value = self.mock_address
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        # Set expire time to yesterday
        self.app.config.freja_expire_time_hours = -24

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        # Check that the expired proofing state was removed
        with self.assertRaises(DocumentDoesNotExist):
            self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_seleg_locked_identity(self, mock_request_user_sync, mock_oidc_call):
        mock_oidc_call.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        # User with no locked_identity
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        # User with locked_identity and correct nin
        user.locked_identity.add(
            LockedIdentityNin.from_dict(dict(number=self.test_user_nin, created_by='test', created_ts=True))
        )
        self.app.central_userdb.save(user, check_sync=False)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        # User with locked_identity and incorrect nin
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': '200102031234', 'csrf_token': csrf_token}
            response = browser.post('/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_PROOFING_FAIL')

    @patch('eduid_webapp.oidc_proofing.helpers.do_authn_request')
    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_freja_locked_identity(self, mock_request_user_sync, mock_oidc_call):
        mock_oidc_call.return_value = True
        mock_request_user_sync.side_effect = self.request_user_sync
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = json.loads(browser.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        user.locked_identity.add(
            LockedIdentityNin.from_dict(dict(number=self.test_user_nin, created_by='test', created_ts=True))
        )
        self.app.central_userdb.save(user, check_sync=False)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': self.test_user_nin, 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

        csrf_token = response['payload']['csrf_token']

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            data = {'nin': '200102031234', 'csrf_token': csrf_token}
            response = browser.post('/freja/proofing', data=json.dumps(data), content_type=self.content_type_json)
            response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_OIDC_PROOFING_FREJA_PROOFING_FAIL')
