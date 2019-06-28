# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import unittest

from eduid_common.api.testing import EtcdTemporaryInstance
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.config.idp import IdPConfig


class TestTypedConfig(unittest.TestCase):

    def setUp(self):
        self.etcd_instance = EtcdTemporaryInstance()

        self.common_ns = '/common/'
        self.idp_ns = '/idp/'
        self.common_parser = EtcdConfigParser(namespace=self.common_ns, host=self.etcd_instance.host, port=self.etcd_instance.port)
        self.idp_parser = EtcdConfigParser(namespace=self.idp_ns, host=self.etcd_instance.host, port=self.etcd_instance.port)

        common_config = {
            'common': {
                'devel_mode': True
            }
        }

        idp_config = {
            'idp': {
                'signup_link': 'dummy'
            }
        }
        self.common_parser.write_configuration(common_config)
        self.idp_parser.write_configuration(idp_config)
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/common/'
        os.environ['EDUID_CONFIG_NS'] = '/idp/'
        os.environ['ETCD_HOST'] = self.etcd_instance.host
        os.environ['ETCD_PORT'] = str(self.etcd_instance.port)

    def tearDown(self):
        self.etcd_instance.shutdown()

    def test_default_setting(self):
        config = IdPConfig.init_config(test_config={})
        self.assertEqual(config.devel_mode, False)
        self.assertEqual(config.debug, True)
        self.assertEqual(config.signup_link, '#')

    def test_test_setting(self):
        config = IdPConfig.init_config(test_config={'devel_mode': True})
        self.assertEqual(config.devel_mode, True)

    def test_etcd_setting(self):
        config = IdPConfig.init_config()
        self.assertEqual(config.signup_link, 'dummy')
        self.assertEqual(config.devel_mode, True)

    def test_debug(self):
        config = IdPConfig.init_config(debug=False)
        self.assertEqual(config.debug, False)
