# -*- coding: utf-8 -*-
import os
import unittest

from eduid_common.config.base import EduIDBaseAppConfig, FlaskConfig, RootConfig
from eduid_common.config.parsers import load_config
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.config.testing import EtcdTemporaryInstance


class TestTypedFlaskConfig(unittest.TestCase):
    def setUp(self):
        self.etcd_instance = EtcdTemporaryInstance.get_instance()

        self.common_ns = '/eduid/webapp/common/'
        self.authn_ns = '/eduid/webapp/authn/'
        self.common_parser = EtcdConfigParser(
            namespace=self.common_ns, host=self.etcd_instance.host, port=self.etcd_instance.port, silent=True,
        )
        self.authn_parser = EtcdConfigParser(
            namespace=self.authn_ns, host=self.etcd_instance.host, port=self.etcd_instance.port, silent=True,
        )

        self.common_config = {'eduid': {'webapp': {'common': {'testing': True, 'preferred_url_scheme': 'https'}}}}

        self.authn_config = {
            'eduid': {
                'webapp': {
                    'authn': {
                        'app_name': 'authn',
                        'safe_relay_domain': 'eduid.se',
                        'application_root': '/services/authn',
                        'mongo_uri': 'mongodb://',
                        'token_service_url': 'token-token',
                        'not-a-valid-setting': False,
                        'secret_key': 'set to trigger creation of config.flask',
                    }
                }
            }
        }
        self.common_parser.write_configuration(self.common_config)
        self.authn_parser.write_configuration(self.authn_config)
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/webapp/common/'
        os.environ['EDUID_CONFIG_NS'] = '/eduid/webapp/authn/'
        os.environ['ETCD_HOST'] = self.etcd_instance.host
        os.environ['ETCD_PORT'] = str(self.etcd_instance.port)

    def tearDown(self) -> None:
        self.etcd_instance.clear('/eduid')

    def test_base_default_setting(self):
        etcd_config = dict(self.common_parser.read_configuration(self.common_parser.ns))
        etcd_config.update(self.authn_parser.read_configuration(self.authn_parser.ns))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = RootConfig(**etcd_config)
        assert config.debug == False

    def test_flask_default_setting(self):
        etcd_config = dict(self.common_parser.read_configuration(self.common_parser.ns))
        etcd_config.update(self.authn_parser.read_configuration(self.authn_parser.ns))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = EduIDBaseAppConfig(**etcd_config)
        self.assertEqual(config.flask.session_refresh_each_request, True)

    def test_override_setting(self):
        etcd_config = dict(self.common_parser.read_configuration(self.common_parser.ns))
        etcd_config.update(self.authn_parser.read_configuration(self.authn_parser.ns))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = EduIDBaseAppConfig(**etcd_config)
        assert config.testing == True

    def test_set_setting(self):
        config = EduIDBaseAppConfig(
            **{'app_name': 'foo', 'mongo_uri': 'X', 'token_service_url': 'aa', 'testing': False}
        )
        assert config.testing == False

    def test_common_etcd_setting(self):
        etcd_config = dict(self.common_parser.read_configuration(self.common_parser.ns))
        etcd_config.update(self.authn_parser.read_configuration(self.authn_parser.ns))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = FlaskConfig(**etcd_config)
        self.assertEqual(config.preferred_url_scheme, 'https')

    def test_specific_etcd_setting(self):
        config = load_config(typ=EduIDBaseAppConfig, app_name='testing', ns='webapp')
        assert config.flask.application_root == '/services/authn'

    def test_filter_load_config(self):
        self.common_config['eduid']['webapp']['common']['not_a_valid_setting'] = True
        self.authn_config['eduid']['webapp']['authn']['token_service_url'] = 'abc123'
        self.common_parser.write_configuration(self.common_config)
        self.authn_parser.write_configuration(self.authn_config)
        config = load_config(typ=EduIDBaseAppConfig, app_name='testing', ns='webapp')
        assert config.token_service_url == 'abc123'
