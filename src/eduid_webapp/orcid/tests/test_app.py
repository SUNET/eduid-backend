# -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_userdb.proofing import ProofingUser
from eduid_userdb.orcid import Orcid, OidcAuthorization, OidcIdToken
from eduid_webapp.orcid.app import init_orcid_app
from eduid_webapp.orcid.settings.common import OrcidConfig

__author__ = 'lundberg'


class OrcidTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.test_user_eppn = 'hubba-bubba'
        self.oidc_provider_config = {
            'token_endpoint_auth_signing_alg_values_supported': [
                'RS256'
            ],
            'id_token_signing_alg_values_supported': [
                'RS256'
            ],
            'userinfo_endpoint': 'https://https://example.com/op/oauth/userinfo',
            'authorization_endpoint': 'https://example.com/op/oauth/authorize',
            'token_endpoint': 'https://example.com/op/oauth/token',
            'jwks_uri': 'https://example.com/op/oauth/jwks',
            'claims_supported': [
                'family_name',
                'given_name',
                'name',
                'auth_time',
                'iss',
                'sub'
            ],
            'scopes_supported': [
                'openid'
            ],
            'subject_types_supported': [
                'public'
            ],
            'response_types_supported': [
                'code'
            ],
            'claims_parameter_supported': False,
            'token_endpoint_auth_methods_supported': [
                'client_secret_basic'
            ],
            'issuer': 'https://example.com/op/'
        }

        class MockResponse(object):
            def __init__(self, status_code, text):
                self.status_code = status_code
                self.text = text

        self.oidc_provider_config_response = MockResponse(200, json.dumps(self.oidc_provider_config))

        self.oidc_id_token = OidcIdToken(iss='iss', sub='sub', aud=['aud'], exp=0, iat=0, nonce='nonce', auth_time=0,
                                         application='orcid')
        self.oidc_authz = OidcAuthorization(access_token='access_token', token_type='token_type',
                                            id_token=self.oidc_id_token, expires_in=0, refresh_token='refresh_token',
                                            application='orcid')
        self.orcid_element = Orcid(id='https://sandbox.orcid.org/0000-0000-0000-0000', name=None, given_name='Test',
                                   family_name='Testsson', verified=True, oidc_authz=self.oidc_authz,
                                   application='orcid')

        super(OrcidTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        with patch('oic.oic.Client.http_request') as mock_response:
            mock_response.return_value = self.oidc_provider_config_response
            return init_orcid_app('testing', config)

    def update_config(self, app_config):
        app_config.update({
            'am_broker_url': 'amqp://dummy',
            'celery_config': {
                'result_backend': 'amqp',
                'task_serializer': 'json'
            },
            'provider_configuration_info': {
                'issuer': 'https://example.com/op/'
            },
            'client_registration_info': {
                'client_id': 'test_client',
                'client_secret': 'secret'
            },
            'userinfo_endpoint_method': 'GET',
            'orcid_verify_redirect_url': 'https://dashboard.example.com/'
        })
        return OrcidConfig(**app_config)

    @patch('oic.oic.Client.parse_response')
    @patch('oic.oic.Client.do_user_info_request')
    @patch('oic.oic.Client.do_access_token_request')
    def mock_authorization_response(self, proofing_state, userinfo, mock_token_request, mock_userinfo_request,
                                    mock_auth_response):
        mock_auth_response.return_value = {
            'id_token': 'id_token',
            'code': 'code',
            'state': proofing_state.state,
        }

        mock_token_request.return_value = {
            'access_token': 'access_token',
            'token_type': 'token_type',
            'expires_in': 0,
            'refresh_token': 'refresh_token',
            'id_token': {
                'nonce': proofing_state.nonce,
                'sub': 'sub',
                'iss': 'iss',
                'aud': [
                    'aud'
                ],
                'exp': 0,
                'iat': 0,
                'auth_time': 0,
                'acr': 'acr',
                'amr': [
                    'amr'
                ],
                'azp': 'azp',
            }
        }
        userinfo['sub'] = 'sub'
        mock_userinfo_request.return_value = userinfo
        return self.browser.get('/authorization-response?id_token=id_token&state={}'.format(proofing_state.state))

    def test_authenticate(self):
        response = self.browser.get('/authorize')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        self.assertTrue(response.location.startswith(self.app.config.token_service_url))
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/authorize')
        self.assertEqual(response.status_code, 302)  # Authenticated request redirected to OP
        self.assertTrue(response.location.startswith(self.app.config.provider_configuration_info['issuer']))

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_oidc_flow(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/authorize')
        self.assertEqual(response.status_code, 302)  # Authenticated request redirected to OP

        # Fake callback from OP
        proofing_state = self.app.proofing_statedb.get_state_by_eppn(self.test_user_eppn)
        userinfo = {
            'id': 'https://sandbox.orcid.org/0000-0000-0000-0000',
            'name': None,
            'given_name': 'Test',
            'family_name': 'Testsson'
        }
        self.mock_authorization_response(proofing_state, userinfo)

        user = self.app.private_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.orcid.id, userinfo['id'])
        self.assertEqual(user.orcid.name, userinfo['name'])
        self.assertEqual(user.orcid.given_name, userinfo['given_name'])
        self.assertEqual(user.orcid.family_name, userinfo['family_name'])
        self.assertEqual(self.app.proofing_log.db_count(), 1)

    def test_get_orcid(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        proofing_user = ProofingUser.from_user(user, self.app.private_userdb)
        proofing_user.orcid = self.orcid_element
        self.request_user_sync(proofing_user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/')
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.data)
        self.assertEqual(response['type'], 'GET_ORCID_SUCCESS')
        self.assertEqual(response['payload']['orcid']['id'], self.orcid_element.id)
        self.assertEqual(response['payload']['orcid']['name'], self.orcid_element.name)
        self.assertEqual(response['payload']['orcid']['given_name'], self.orcid_element.given_name)
        self.assertEqual(response['payload']['orcid']['family_name'], self.orcid_element.family_name)

    @patch('eduid_common.api.am.AmRelay.request_user_sync')
    def test_remove_orcid(self, mock_request_user_sync):
        mock_request_user_sync.side_effect = self.request_user_sync

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        proofing_user = ProofingUser.from_user(user, self.app.private_userdb)
        proofing_user.orcid = self.orcid_element
        self.request_user_sync(proofing_user)

        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/')
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.data)
        self.assertEqual(response['type'], 'GET_ORCID_SUCCESS')

        csrf_token = response['payload']['csrf_token']
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.post('/remove', data={'csrf_token': csrf_token})
        self.assertEqual(response.status_code, 200)
        response = json.loads(response.data)
        self.assertEqual(response['type'], 'POST_ORCID_REMOVE_SUCCESS')

        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        self.assertEqual(user.orcid, None)
