# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2019 SUNET
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

import json
import os
from pathlib import PurePath
from typing import Any, Dict, Mapping

from eduid.common.config.parsers import load_config
from eduid.common.misc.tous import get_tous
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.jsconfig.app import JSConfigApp, jsconfig_init_app
from eduid.webapp.jsconfig.settings.common import JSConfigConfig
from eduid.webapp.jsconfig.settings.jsapps import JsAppsConfig


class JSConfigTests(EduidAPITestCase):

    app: JSConfigApp

    def setUp(self):
        self.data_dir = str(PurePath(__file__).with_name('data'))
        super(JSConfigTests, self).setUp(copy_user_to_private=False)

    def load_app(self, config: Mapping[str, Any]) -> JSConfigApp:
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        app = jsconfig_init_app(test_config=config)
        self.browser = app.test_client(allow_subdomain_redirects=True)
        app.url_map.host_matching = False
        return app

    def update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        config.update(
            {
                'server_name': 'example.com',
                'testing': True,
                'jsapps': {
                    'password_entropy': 12,
                    'password_length': 10,
                    'authn_url': 'authn_url',
                    'dashboard_url': 'dashboard_url',
                    'eidas_url': 'eidas_url',
                    'emails_url': 'emails_url',
                    'group_mgmt_url': 'group_mgmt_url',
                    'letter_proofing_url': 'letter_proofing_url',
                    'login_next_url': 'login_next_url',
                    'lookup_mobile_proofing_url': 'lookup_mobile_proofing_url',
                    'oidc_proofing_freja_url': 'oidc_proofing_freja_url',
                    'oidc_proofing_url': 'oidc_proofing_url',
                    'orcid_url': 'orcid_url',
                    'personal_data_url': 'personal_data_url',
                    'phone_url': 'phone_url',
                    'reset_password_url': 'reset_password_url',
                    'security_url': 'security_url',
                    'signup_url': 'signup_url',
                    'static_faq_url': 'static_faq_url',
                    'token_verify_idp': 'token_verify_idp',
                    'reset_password_link': 'reset_password_link',
                },
            }
        )
        return config

    def test_get_dashboard_config(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn, server_name='example.com', subdomain='dashboard') as client:
            response = client.get('http://dashboard.example.com/config')

            self.assertEqual(response.status_code, 200)

            config_data = json.loads(response.data)

            assert config_data['type'] == 'GET_JSCONFIG_CONFIG_SUCCESS'
            assert config_data['payload']['dashboard_url'] == 'dashboard_url'
            assert config_data['payload']['personal_data_url'] == 'personal_data_url'
            assert config_data['payload']['static_faq_url'] == 'static_faq_url'
            assert config_data['payload']['available_languages'] == [['en', 'English'], ['sv', 'Svenska']]

            assert config_data['payload']['DASHBOARD_URL'] == 'dashboard_url'
            assert config_data['payload']['PERSONAL_DATA_URL'] == 'personal_data_url'
            assert config_data['payload']['STATIC_FAQ_URL'] == 'static_faq_url'
            assert config_data['payload']['AVAILABLE_LANGUAGES'] == [['en', 'English'], ['sv', 'Svenska']]

    def test_get_signup_config(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn, server_name='example.com', subdomain='signup') as client:
            response = client.get('http://signup.example.com/signup/config')

            self.assertEqual(response.status_code, 200)

            config_data = json.loads(response.data)

            assert config_data['type'] == 'GET_JSCONFIG_SIGNUP_CONFIG_SUCCESS'
            assert config_data['payload']['dashboard_url'] == 'dashboard_url'
            assert config_data['payload']['static_faq_url'] == 'static_faq_url'
            assert config_data['payload']['tous'] == get_tous(
                self.app.conf.tou_version, self.app.conf.available_languages.keys()
            )
            assert config_data['payload']['available_languages'] == [['en', 'English'], ['sv', 'Svenska']]

            assert config_data['payload']['DASHBOARD_URL'] == 'dashboard_url'
            assert config_data['payload']['STATIC_FAQ_URL'] == 'static_faq_url'
            assert config_data['payload']['TOUS'] == get_tous(
                self.app.conf.tou_version, self.app.conf.available_languages.keys()
            )
            assert config_data['payload']['AVAILABLE_LANGUAGES'] == [['en', 'English'], ['sv', 'Svenska']]

    def test_get_login_config(self):

        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn, server_name='example.com', subdomain='login') as client:
            response = client.get('http://login.example.com/login/config')

            self.assertEqual(response.status_code, 200)

            config_data = json.loads(response.data)

            assert config_data['type'] == 'GET_JSCONFIG_LOGIN_CONFIG_SUCCESS'
            assert config_data['payload']['password_entropy'] == 12
            assert config_data['payload']['password_length'] == 10

    def test_jsapps_config_from_yaml(self):
        os.environ['EDUID_CONFIG_YAML'] = f'{self.data_dir}/config.yaml'

        config = load_config(typ=JSConfigConfig, app_name='jsconfig', ns='webapp')
        assert self.app.conf.jsapps.dict() == config.jsapps.dict()
