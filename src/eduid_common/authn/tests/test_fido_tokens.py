# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#


import json
from copy import deepcopy
from dataclasses import dataclass, field
from typing import cast

from flask import Blueprint, current_app, request
from mock import patch

from eduid_userdb import User
from eduid_userdb.credentials import U2F, Webauthn
from eduid_userdb.data_samples import NEW_USER_EXAMPLE

from eduid_common.api.app import EduIDBaseApp
from eduid_common.api.testing import EduidAPITestCase
from eduid_common.authn.fido_tokens import VerificationProblem, start_token_verification, verify_webauthn
from eduid_common.config.base import FlaskConfig


@dataclass
class MockFidoConfig(FlaskConfig):
    mfa_testing: bool = True
    generate_u2f_challenges: bool = True
    u2f_app_id: str = 'https://eduid.se/u2f-app-id.json'
    fido2_rp_id: str = 'idp.dev.eduid.se'
    u2f_valid_facets: list = field(
        default_factory=lambda: ['https://dashboard.dev.eduid.se', 'https://idp.dev.eduid.se']
    )


views = Blueprint('testing', 'testing', url_prefix='')


@views.route('/start', methods=["GET"])
def start_verification():
    user = current_app.central_userdb.get_user_by_eppn('hubba-bubba')
    data = json.loads(request.query_string[17:])
    try:
        result = verify_webauthn(user, data, 'testing')
    except VerificationProblem:
        result = {'success': False, 'message': 'mfa.verification-problem'}
    return json.dumps(result)


class MockFidoApp(EduIDBaseApp):
    def __init__(self, name: str, config: dict, **kwargs):
        self.config = MockFidoConfig(**config)
        super(MockFidoApp, self).__init__(name, **kwargs)
        self.config: MockFidoConfig = cast(MockFidoConfig, self.config)
        self.register_blueprint(views)


SAMPLE_WEBAUTHN_REQUEST = {
    'authenticatorData': 'EqW1xI3n-hgnNPFAHqXwTnBqgKgUMmBLDxB7n3apMPQAAAAAAA',
    'clientDataJSON': 'eyJjaGFsbGVuZ2UiOiIzaF9FQVpwWTI1eERkU0pDT014MUFCWkVBNU9kejN5ZWpVSTNBVU5UUVdjIiwib3JpZ2luIjoiaHR0cHM6Ly9pZHAuZGV2LmVkdWlkLnNlIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9',
    'credentialId': 'i3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_Q',
    #  This is a fake signature, we mock its verification below
    'signature': 'MEYCIQC5gM8inamJGUFKu3bNo4fT0jmJQuw33OSSXc242NCuiwIhAIWnVw2Spow72j6J92KaY2rLR6qSXEbLam09ZXbSkBnQ',
}


SAMPLE_WEBAUTHN_CREDENTIAL = {
    'keyhandle': 'i3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_Q',
    'credential_data': 'AAAAAAAAAAAAAAAAAAAAAABAi3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_aUBAgMmIAEhWCCiwDYGxl1LnRMqooWm0aRR9YbBG2LZ84BMNh_4rHkA9yJYIIujMrUOpGekbXjgMQ8M13ZsBD_cROSPB79eGz2Nw1ZE',
    'app_id': '',
    'attest_obj': 'bzJObWJYUmtibTl1WldkaGRIUlRkRzEwb0doaGRYUm9SR0YwWVZqRXhvVGI1OVBlcEV0YW9PYWY5RDlOUjIxVWJfSU5PT0tfVDdubDFuZHNIUlJCQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVFJdHlvd1U5TGVVejV1dmQwX1R0SC1NOG9zTDNidlhHUEFYb0FvNGxiNnZ4VXZtWmozTDE0cVJieDd3LVFoLW1WVVVkNTdGYkRwV3RBbW5kMzI3VkFQMmxBUUlESmlBQklWZ2dvc0EyQnNaZFM1MFRLcUtGcHRHa1VmV0d3UnRpMmZPQVREWWYtS3g1QVBjaVdDQ0xveksxRHFSbnBHMTQ0REVQRE5kMmJBUV8zRVRrandlX1hoczlqY05XUkE=',
    'description': 'unit test webauthn token',
}

SAMPLE_U2F_CREDENTIAL = {
    'version': 'U2F_V2',
    'keyhandle': 'V1vXqZcwBJD2RMIH2udd2F7R9NoSNlP7ZSPOtKHzS7n_rHFXcXbSpOoX__aUKyTR6jEC8Xv678WjXC5KEkvziA',
    'public_key': 'BHVTWuo3_D7ruRBe2Tw-m2atT2IOm_qQWSDreWShu3t21ne9c-DPSUdym-H-t7FcjV7rj1dSc3WSwaOJpFmkKxQ',
    'app_id': 'https://eduid.se/u2f-app-id.json',
    'attest_cert': '',
    'description': 'unit test U2F token',
}


class FidoTokensTestCase(EduidAPITestCase):
    def setUp(self):
        super(FidoTokensTestCase, self).setUp()
        self.webauthn_credential = Webauthn(**SAMPLE_WEBAUTHN_CREDENTIAL)
        self.u2f_credential = U2F(**SAMPLE_U2F_CREDENTIAL)

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return MockFidoApp('testing', config)

    def update_config(self, app_config):
        app_config.update(
            {
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'celery_config': {
                    'result_backend': 'amqp',
                    'task_serializer': 'json',
                    'mongo_uri': app_config['mongo_uri'],
                },
            }
        )
        return MockFidoConfig(**app_config)

    def test_u2f_start_verification(self):
        test_user = User.from_dict(data=NEW_USER_EXAMPLE)
        # Add a working U2F credential for this test
        test_user.credentials.add(self.u2f_credential)
        self.amdb.save(test_user, check_sync=False)

        eppn = test_user.eppn

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    config = start_token_verification(test_user, 'testing')
                    self.assertEqual(json.loads(config['u2fdata'])["appId"], "https://eduid.se/u2f-app-id.json")

    def test_webauthn_start_verification(self):
        test_user = User.from_dict(data=NEW_USER_EXAMPLE)
        # Add a working U2F credential for this test
        test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(test_user, check_sync=False)

        eppn = test_user.eppn

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    config = start_token_verification(test_user, 'testing')
                    self.assertEqual(json.loads(config['u2fdata']), {})

    @patch('fido2.cose.ES256.verify')
    def test_webauthn_verify(self, mock_verify):
        mock_verify.return_value = True
        test_user = User.from_dict(data=NEW_USER_EXAMPLE)
        # Add a working U2F credential for this test
        test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(test_user, check_sync=False)

        eppn = test_user.eppn

        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    fido2state = {
                        'challenge': '3h_EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc',
                        'user_verification': 'preferred',
                    }
                    sess['testing.webauthn.state'] = json.dumps(fido2state)
                    sess.persist()
                    resp = client.get('/start?webauthn_request=' + json.dumps(SAMPLE_WEBAUTHN_REQUEST))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data['success'], True)

    @patch('fido2.cose.ES256.verify')
    def test_webauthn_verify_wrong_origin(self, mock_verify):
        self.app.config.fido2_rp_id = 'wrong.rp.id'
        mock_verify.return_value = True
        test_user = User.from_dict(data=NEW_USER_EXAMPLE)
        # Add a working U2F credential for this test
        test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(test_user, check_sync=False)

        eppn = test_user.eppn

        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    fido2state = {
                        'challenge': '3h_EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc',
                        'user_verification': 'preferred',
                    }
                    sess['testing.webauthn.state'] = json.dumps(fido2state)
                    sess.persist()
                    resp = client.get('/start?webauthn_request=' + json.dumps(SAMPLE_WEBAUTHN_REQUEST))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data['success'], False)

    @patch('fido2.cose.ES256.verify')
    def test_webauthn_verify_wrong_challenge(self, mock_verify):
        mock_verify.return_value = True
        test_user = User.from_dict(data=NEW_USER_EXAMPLE)
        # Add a working U2F credential for this test
        test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(test_user, check_sync=False)

        eppn = test_user.eppn

        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    fido2state = {
                        'challenge': 'WRONG_CHALLENGE_COx1ABZEA5Odz3yejUI3AUNTQWc',
                        'user_verification': 'preferred',
                    }
                    sess['testing.webauthn.state'] = json.dumps(fido2state)
                    sess.persist()
                    resp = client.get('/start?webauthn_request=' + json.dumps(SAMPLE_WEBAUTHN_REQUEST))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data['success'], False)

    @patch('fido2.cose.ES256.verify')
    def test_webauthn_verify_wrong_credential(self, mock_verify):
        req = deepcopy(SAMPLE_WEBAUTHN_REQUEST)
        req['credentialId'] = req['credentialId'].replace('0', '9')
        mock_verify.return_value = True
        test_user = User.from_dict(data=NEW_USER_EXAMPLE)
        # Add a working U2F credential for this test
        test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(test_user, check_sync=False)

        eppn = test_user.eppn

        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    fido2state = {
                        'challenge': '3h_EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc',
                        'user_verification': 'preferred',
                    }
                    sess['testing.webauthn.state'] = json.dumps(fido2state)
                    sess.persist()
                    resp = client.get('/start?webauthn_request=' + json.dumps(req))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data['success'], False)
