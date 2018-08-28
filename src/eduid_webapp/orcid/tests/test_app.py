# -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
from mock import patch

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.orcid.app import init_orcid_app

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

        super(OrcidTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        with patch('oic.oic.Client.http_request') as mock_response:
            mock_response.return_value = self.oidc_provider_config_response
            return init_orcid_app('testing', config)

    def update_config(self, config):
        config.update({
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
            'USERINFO_ENDPOINT_METHOD': 'GET',
        })
        return config

    def tearDown(self):
        super(OrcidTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()

    def test_authenticate(self):
        response = self.browser.get('/authorize')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        self.assertTrue(response.location.startswith(self.app.config['TOKEN_SERVICE_URL']))
        with self.session_cookie(self.browser, self.test_user_eppn) as browser:
            response = browser.get('/authorize')
        self.assertEqual(response.status_code, 302)  # Authenticated request redirected to OP
        self.assertTrue(response.location.startswith(self.app.config['PROVIDER_CONFIGURATION_INFO']['issuer']))
