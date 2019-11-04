# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import unittest

from eduid_common.config.testing import EtcdTemporaryInstance
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.config.idp import IdPConfig
from eduid_common.config.base import FlaskConfig


class TestTypedIdPConfig(unittest.TestCase):

    def setUp(self):
        self.etcd_instance = EtcdTemporaryInstance.get_instance()

        self.common_ns = '/eduid/webapp/common/'
        self.idp_ns = '/eduid/webapp/idp/'
        self.common_parser = EtcdConfigParser(namespace=self.common_ns, host=self.etcd_instance.host, port=self.etcd_instance.port)
        self.idp_parser = EtcdConfigParser(namespace=self.idp_ns, host=self.etcd_instance.host, port=self.etcd_instance.port)

        common_config = {
            'eduid': {
                'webapp': {
                    'common': {
                        'devel_mode': True
                    }
                }
            }
        }

        idp_config = {
            'eduid': {
                'webapp': {
                    'idp': {
                        'signup_link': 'dummy'
                    }
                }
            }
        }
        self.common_parser.write_configuration(common_config)
        self.idp_parser.write_configuration(idp_config)
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/webapp/common/'
        os.environ['EDUID_CONFIG_NS'] = '/eduid/webapp/idp/'
        os.environ['ETCD_HOST'] = self.etcd_instance.host
        os.environ['ETCD_PORT'] = str(self.etcd_instance.port)

    def test_default_setting(self):
        config = IdPConfig(app_name='idp')
        self.assertEqual(config.devel_mode, False)
        self.assertEqual(config.debug, False)
        self.assertEqual(config.signup_link, '#')

    def test_test_setting(self):
        config = IdPConfig(**{'app_name': 'idp', 'devel_mode': True})
        self.assertEqual(config.devel_mode, True)

    def test_etcd_setting(self):
        etcd_config = self.common_parser.read_configuration(silent=True)
        etcd_config.update(self.idp_parser.read_configuration(silent=True))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = IdPConfig(**etcd_config)
        self.assertEqual(config.signup_link, 'dummy')
        self.assertEqual(config.devel_mode, True)


class TestTypedFlaskConfig(unittest.TestCase):

    def setUp(self):
        self.etcd_instance = EtcdTemporaryInstance.get_instance()

        self.common_ns = '/eduid/webapp/common/'
        self.authn_ns = '/eduid/webapp/authn/'
        self.common_parser = EtcdConfigParser(namespace=self.common_ns, host=self.etcd_instance.host, port=self.etcd_instance.port)
        self.authn_parser = EtcdConfigParser(namespace=self.authn_ns, host=self.etcd_instance.host, port=self.etcd_instance.port)

        common_config = {
            'eduid': {
                'webapp': {
                    'common': {
                        'devel_mode': True,
                        'preferred_url_scheme': 'https'
                    }
                }
            }
        }

        authn_config = {
            'eduid': {
                'webapp': {
                    'authn': {
                        'safe_relay_domain': 'eduid.se',
                        'application_root': '/services/authn'
                    }
                }
            }
        }
        self.common_parser.write_configuration(common_config)
        self.authn_parser.write_configuration(authn_config)
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/webapp/common/'
        os.environ['EDUID_CONFIG_NS'] = '/eduid/webapp/authn/'
        os.environ['ETCD_HOST'] = self.etcd_instance.host
        os.environ['ETCD_PORT'] = str(self.etcd_instance.port)

    def test_base_default_setting(self):
        etcd_config = self.common_parser.read_configuration(silent=True)
        etcd_config.update(self.authn_parser.read_configuration(silent=True))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = FlaskConfig(**etcd_config)
        self.assertEqual(config.log_backup_count, 10)
        self.assertEqual(config['log_backup_count'], 10)

    def test_flask_default_setting(self):
        etcd_config = self.common_parser.read_configuration(silent=True)
        etcd_config.update(self.authn_parser.read_configuration(silent=True))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = FlaskConfig(**etcd_config)
        self.assertEqual(config.session_refresh_each_request, True)
        self.assertEqual(config['session_refresh_each_request'], True)

    def test_override_setting(self):
        etcd_config = self.common_parser.read_configuration(silent=True)
        etcd_config.update(self.authn_parser.read_configuration(silent=True))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = FlaskConfig(**etcd_config)
        self.assertEqual(config.devel_mode, True)
        self.assertEqual(config['devel_mode'], True)

    def test_set_setting(self):
        config = FlaskConfig(**{'log_backup_count': 100})
        self.assertEqual(config.log_backup_count, 100)
        self.assertEqual(config['log_backup_count'], 100)

    def test_common_etcd_setting(self):
        etcd_config = self.common_parser.read_configuration(silent=True)
        etcd_config.update(self.authn_parser.read_configuration(silent=True))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = FlaskConfig(**etcd_config)
        self.assertEqual(config.preferred_url_scheme, 'https')
        self.assertEqual(config['preferred_url_scheme'], 'https')

    def test_specific_etcd_setting(self):
        etcd_config = self.common_parser.read_configuration(silent=True)
        etcd_config.update(self.authn_parser.read_configuration(silent=True))
        etcd_config = {key.lower(): value for key, value in etcd_config.items()}
        config = FlaskConfig(**etcd_config)
        self.assertEqual(config.application_root, '/services/authn')
        self.assertEqual(config['application_root'], '/services/authn')
