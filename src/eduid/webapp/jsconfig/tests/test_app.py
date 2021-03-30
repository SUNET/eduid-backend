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
from eduid.common.config.parsers.etcd import EtcdConfigParser
from eduid.common.misc.tous import get_tous
from eduid.webapp.common.api.testing import EduidAPITestCase
from eduid.webapp.jsconfig.app import JSConfigApp, jsconfig_init_app
from eduid.webapp.jsconfig.settings.front import FrontConfig


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
                'tou_url': 'dummy-url',
                'testing': True,
                'dashboard_bundle_path': 'dummy-dashboard-bundle',
                'dashboard_bundle_version': 'dummy-dashboard-version',
                'signup_bundle_path': 'dummy-signup-bundle',
                'signup_bundle_version': 'dummy-signup-version',
                'login_bundle_path': 'dummy-login-bundle',
                'login_bundle_version': 'dummy-login-version',
                'eduid_static_url': '/static',
                # config for jsapps
                'password_entropy': 12,
                'password_length': 10,
                'dashboard_url': 'dummy-url',
                'personal_data_url': 'personal-data-url',
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
            assert config_data['payload']['dashboard_url'] == 'dummy-url'
            assert config_data['payload']['personal_data_url'] == 'personal-data-url'
            assert config_data['payload']['static_faq_url'] == ''
            assert config_data['payload']['available_languages'] == [['en', 'English'], ['sv', 'Svenska']]

            assert config_data['payload']['DASHBOARD_URL'] == 'dummy-url'
            assert config_data['payload']['PERSONAL_DATA_URL'] == 'personal-data-url'
            assert config_data['payload']['STATIC_FAQ_URL'] == ''
            assert config_data['payload']['AVAILABLE_LANGUAGES'] == [['en', 'English'], ['sv', 'Svenska']]

    def test_get_signup_config(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn, server_name='example.com', subdomain='signup') as client:
            response = client.get('http://signup.example.com/signup/config')

            self.assertEqual(response.status_code, 200)

            config_data = json.loads(response.data)

            assert config_data['type'] == 'GET_JSCONFIG_SIGNUP_CONFIG_SUCCESS'
            assert config_data['payload']['dashboard_url'] == 'dummy-url'
            assert config_data['payload']['static_faq_url'] == ''
            assert config_data['payload']['tous'] == get_tous(
                self.app.conf.tou_version, self.app.conf.available_languages.keys()
            )
            assert config_data['payload']['available_languages'] == [['en', 'English'], ['sv', 'Svenska']]

            assert config_data['payload']['DASHBOARD_URL'] == 'dummy-url'
            assert config_data['payload']['STATIC_FAQ_URL'] == ''
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

    def test_get_dashboard_bundle(self):
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn, server_name='example.com', subdomain='dashboard') as client:
            response = client.get('http://dashboard.example.com/get-bundle')

            self.assertEqual(response.status_code, 200)

            body = response.data
            assert 'dummy-dashboard-bundle' in str(body)
            assert 'dummy-dashboard-version' in str(body)

    def test_get_signup_bundle(self):
        # XXX Here we access the view by exposing it in a different path - the
        # production manner of distinguishing it (throught its subdomain) does
        # not work with the test client
        from eduid.webapp.jsconfig import views

        views.jsconfig_views.route('/get-signup-bundle', methods=['GET'])(views.get_signup_bundle)
        self.app.register_blueprint(views.jsconfig_views)
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response = client.get('http://signup.example.com/get-signup-bundle')

            self.assertEqual(response.status_code, 200)

            body = response.data
            assert 'dummy-signup-bundle' in str(body)
            assert 'dummy-signup-version' in str(body)

    def test_get_login_bundle(self):
        # XXX Here we access the view by exposing it in a different path - the
        # production manner of distinguishing it (throught its subdomain) does
        # not work with the test client
        from eduid.webapp.jsconfig import views

        views.jsconfig_views.route('/get-login-bundle', methods=['GET'])(views.get_login_bundle)
        self.app.register_blueprint(views.jsconfig_views)
        eppn = self.test_user_data['eduPersonPrincipalName']
        with self.session_cookie(self.browser, eppn) as client:
            response = client.get('http://login.example.com/get-login-bundle')

            self.assertEqual(response.status_code, 200)

            body = response.data
            assert 'dummy-login-bundle' in str(body)
            assert 'dummy-login-version' in str(body)

    def test_jsapps_config_from_etcd(self):
        common_config_parser = EtcdConfigParser(
            namespace='/eduid/webapp/common/', host=self.etcd_instance.host, port=self.etcd_instance.port
        )
        app_config_parser = EtcdConfigParser(
            namespace='/eduid/webapp/jsapps/', host=self.etcd_instance.host, port=self.etcd_instance.port
        )

        config = {
            'eduid': {
                'webapp': {
                    'common': {'testing': True},
                    'jsapps': {'password_entropy': 0, 'password_length': 1, 'dashboard_url': 'dummy-url-etcd'},
                }
            }
        }
        common_config_parser.write_configuration(config)
        app_config_parser.write_configuration(config)
        os.environ['EDUID_CONFIG_NS'] = '/eduid/webapp/jsapps/'
        os.environ['ETCD_HOST'] = self.etcd_instance.host
        os.environ['ETCD_PORT'] = str(self.etcd_instance.port)

        front_config = load_config(typ=FrontConfig, app_name='jsapps', ns='webapp')
        assert front_config == FrontConfig(
            testing=True, password_entropy=0, password_length=1, dashboard_url='dummy-url-etcd'
        )

    def test_jsapps_config_from_yaml(self):
        os.environ['EDUID_CONFIG_YAML'] = f'{self.data_dir}/config.yaml'

        front_config = load_config(typ=FrontConfig, app_name='jsapps', ns='webapp')
        assert front_config == FrontConfig(
            testing=True,
            password_entropy=2,
            password_length=3,
            dashboard_url='dummy-url-yaml',
            personal_data_url='dummy-personal-data-url',
        )
