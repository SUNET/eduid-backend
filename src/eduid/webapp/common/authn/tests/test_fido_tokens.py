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
import base64
import json
from copy import deepcopy
from typing import Any, Dict, Mapping

from flask import Blueprint, current_app, request
from mock import patch

from eduid.common.config.base import EduIDBaseAppConfig, WebauthnConfigMixin2
from eduid.common.config.parsers import load_config
from eduid.userdb import User
from eduid.userdb.fixtures.fido_credentials import u2f_credential, webauthn_credential
from eduid.userdb.fixtures.users import new_user_example
from eduid.webapp.common.api.app import EduIDBaseApp
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.common.authn.fido_tokens import VerificationProblem, start_token_verification, verify_webauthn


class MockFidoConfig(EduIDBaseAppConfig, WebauthnConfigMixin2):
    mfa_testing: bool = True
    generate_u2f_challenges: bool = True


views = Blueprint('testing', 'testing', url_prefix='')


@views.route('/start', methods=["GET"])
def start_verification():
    current_app.logger.info('Endpoint start_verification called')
    user = current_app.central_userdb.get_user_by_eppn('hubba-bubba')
    data = json.loads(request.query_string[17:])
    try:
        result = verify_webauthn(user, data, current_app.conf.fido2_rp_id).json()
    except VerificationProblem as exc:
        current_app.logger.error(f'Webauthn verification failed: {repr(exc)}')
        result = {'success': False, 'message': 'mfa.verification-problem'}
    current_app.logger.info(f'Endpoint start_verification result: {result}')
    return result


class MockFidoApp(EduIDBaseApp):
    def __init__(self, config: MockFidoConfig):
        super().__init__(config)

        self.conf = config


SAMPLE_WEBAUTHN_REQUEST = {
    'authenticatorData': 'EqW1xI3n-hgnNPFAHqXwTnBqgKgUMmBLDxB7n3apMPQAAAAAAA',
    'clientDataJSON': 'eyJjaGFsbGVuZ2UiOiIzaF9FQVpwWTI1eERkU0pDT014MUFCWkVBNU9kejN5ZWpVSTNBVU5UUVdjIiwib3JpZ2luIjoiaHR0cHM6Ly9pZHAuZGV2LmVkdWlkLnNlIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9',
    'credentialId': 'i3KjBT0t5TPm693T9O0f4zyiwvdu9cY8BegCjiVvq_FS-ZmPcvXipFvHvD5CH6ZVRR3nsVsOla0Cad3fbtUA_Q',
    #  This is a fake signature, we mock its verification below
    'signature': 'MEYCIQC5gM8inamJGUFKu3bNo4fT0jmJQuw33OSSXc242NCuiwIhAIWnVw2Spow72j6J92KaY2rLR6qSXEbLam09ZXbSkBnQ',
}


class FidoTokensTestCase(EduidAPITestCase):

    app: MockFidoApp

    def setUp(self):
        super().setUp()
        self.webauthn_credential = webauthn_credential
        self.u2f_credential = u2f_credential
        self.test_user = User.from_dict(data=new_user_example.to_dict())

    def load_app(self, test_config: Mapping[str, Any]) -> MockFidoApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        config = load_config(typ=MockFidoConfig, app_name='testing', ns='webapp', test_config=test_config)
        app = MockFidoApp(config)
        app.register_blueprint(views)
        return app

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config.update(
            {
                'app_name': 'testing',
                'available_languages': {'en': 'English', 'sv': 'Svenska'},
                'u2f_app_id': 'https://eduid.se/u2f-app-id.json',
                'fido2_rp_id': 'idp.dev.eduid.se',
                'u2f_valid_facets': ['https://dashboard.dev.eduid.se', 'https://idp.dev.eduid.se'],
            }
        )
        return config

    def test_u2f_start_verification(self):
        # Add a working U2F credential for this test
        self.test_user.credentials.add(self.u2f_credential)
        self.amdb.save(self.test_user, check_sync=False)

        eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    config = start_token_verification(self.test_user, self.app.conf.fido2_rp_id)
                    assert 'u2fdata' not in config
                    assert 'webauthn_options' in config
                    s = config['webauthn_options']
                    _decoded = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
                    # _decoded is still CBOR encoded, so we just check for some known strings
                    assert b'publicKey' in _decoded
                    assert b'idp.dev.eduid.se' in _decoded
                    assert b'challenge' in _decoded

    def test_webauthn_start_verification(self):
        # Add a working Webauthn credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user, check_sync=False)

        eppn = self.test_user.eppn

        with self.session_cookie(self.browser, eppn) as client:
            with client.session_transaction():
                with self.app.test_request_context():
                    config = start_token_verification(self.test_user, self.app.conf.fido2_rp_id)
                    assert 'u2fdata' not in config
                    assert 'webauthn_options' in config
                    s = config['webauthn_options']
                    _decoded = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
                    # _decoded is still CBOR encoded, so we just check for some known strings
                    assert b'publicKey' in _decoded
                    assert b'idp.dev.eduid.se' in _decoded
                    assert b'challenge' in _decoded

    @patch('fido2.cose.ES256.verify')
    def test_webauthn_verify(self, mock_verify):
        mock_verify.return_value = True
        # Add a working U2F credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user, check_sync=False)

        eppn = self.test_user.eppn

        with self.app.test_request_context():
            with self.session_cookie(self.browser, eppn) as client:
                with client.session_transaction() as sess:
                    fido2state = {
                        'challenge': '3h_EAZpY25xDdSJCOMx1ABZEA5Odz3yejUI3AUNTQWc',
                        'user_verification': 'preferred',
                    }
                    sess.mfa_action.webauthn_state = fido2state
                    sess.persist()
                    resp = client.get('/start?webauthn_request=' + json.dumps(SAMPLE_WEBAUTHN_REQUEST))
                    resp_data = json.loads(resp.data)
                    self.assertEqual(resp_data['success'], True)

    @patch('fido2.cose.ES256.verify')
    def test_webauthn_verify_wrong_origin(self, mock_verify):
        self.app.conf.fido2_rp_id = 'wrong.rp.id'
        mock_verify.return_value = True
        # Add a working U2F credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user, check_sync=False)

        eppn = self.test_user.eppn

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
        # Add a working U2F credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user, check_sync=False)

        eppn = self.test_user.eppn

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
        # Add a working Webauthn credential for this test
        self.test_user.credentials.add(self.webauthn_credential)
        self.amdb.save(self.test_user, check_sync=False)

        eppn = self.test_user.eppn

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
