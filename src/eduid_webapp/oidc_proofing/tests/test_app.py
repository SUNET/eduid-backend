# -*- coding: utf-8 -*-

from __future__ import absolute_import

from os import devnull
from copy import deepcopy
import json
import jose
from datetime import datetime
from collections import OrderedDict
from mock import patch
from bson import ObjectId
from requests import Response

from eduid_userdb.data_samples import NEW_USER_EXAMPLE
from eduid_userdb.user import User
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.oidc_proofing.app import init_oidc_proofing_app
from eduid_webapp.oidc_proofing.helpers import create_proofing_state

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
        self.client = self.app.test_client()

        # Replace user with one without previous proofings
        userdata = deepcopy(NEW_USER_EXAMPLE)
        del userdata['nins']
        user = User(data=userdata)
        user.modified_ts = True
        self.app.central_userdb.save(user, check_sync=False)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        with patch('oic.oic.Client.http_request') as mock_response:
            mock_response.return_value = self.oidc_provider_config_response
            return init_oidc_proofing_app('testing', config)

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
            'FREJA_RESPONSE_PROTOCOL': '1,0'
        })
        return config

    def tearDown(self):
        super(OidcProofingTests, self).tearDown()
        with self.app.app_context():
            self.app.proofing_statedb._drop_whole_collection()
            self.app.central_userdb._drop_whole_collection()

    def test_authenticate(self):
        response = self.client.get('/proofing')
        self.assertEqual(response.status_code, 302)  # Redirect to token service
        with self.session_cookie(self.client, self.test_user_eppn) as client:
            response = client.get('/proofing')
        self.assertEqual(response.status_code, 200)  # Authenticated request

    def test_empty_state(self):
        with self.session_cookie(self.client, self.test_user_eppn) as client:
            response = json.loads(client.get('/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_PROOFING_SUCCESS')

    def test_empty_freja_state(self):
        with self.session_cookie(self.client, self.test_user_eppn) as client:
            response = json.loads(client.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')

    def test_freja_state(self):
        user = self.app.central_userdb.get_user_by_eppn(self.test_user_eppn)
        proofing_state = create_proofing_state(user, self.test_user_nin)
        self.app.proofing_statedb.save(proofing_state)
        with self.session_cookie(self.client, self.test_user_eppn) as client:
            response = json.loads(client.get('/freja/proofing').data)
        self.assertEqual(response['type'], 'GET_OIDC_PROOFING_FREJA_PROOFING_SUCCESS')
        jwk = {'k': self.app.config['FREJA_JWK_SECRET'].decode('hex')}
        jwt = response['payload']['iaRequestData']
        request_data = jose.verify(jose.deserialize_compact(jwt), jwk, alg=self.app.config['FREJA_JWS_ALGORITHM'])
        self.assertDictEqual(json.loads(request_data), {})
