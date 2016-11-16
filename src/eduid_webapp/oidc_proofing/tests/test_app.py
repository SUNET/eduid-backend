# -*- coding: utf-8 -*-

from __future__ import absolute_import

from os import devnull
from copy import deepcopy
import json
from datetime import datetime
from collections import OrderedDict
from mock import patch
from bson import ObjectId
from requests import Response

from eduid_userdb.data_samples import NEW_USER_EXAMPLE
from eduid_userdb.user import User
from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.oidc_proofing.app import init_oidc_proofing_app

__author__ = 'lundberg'


class AppTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        super(AppTests, self).setUp()

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

        self.client = self.app.test_client()

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
                'issuer': 'https://example.com'
            },
            'CLIENT_REGISTRATION_INFO': {
                'client_id': 'test_client',
                'client_secret': 'secret'
            }
        })
        return config

    def tearDown(self):
        super(AppTests, self).tearDown()
        with self.app.app_context():
            self.app.proofing_statedb._drop_whole_collection()
            self.app.central_userdb._drop_whole_collection()

    #@patch('eduid_webapp.oidc_proofing.app.Client.http_request')
    #def test_authenticate(self, mock_response):
    #    mock_response.return_value = self.oidc_provider_config_response
    #    response = self.client.get('/proofing')
    #    self.assertEqual(response.status_code, 302)  # Redirect to token service
    #    with self.session_cookie(self.client, self.test_user_eppn) as client:
    #        response = client.get('/proofing')
    #    self.assertEqual(response.status_code, 200)  # Authenticated request
