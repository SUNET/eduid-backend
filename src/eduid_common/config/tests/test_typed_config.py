# -*- coding: utf-8 -*-

from __future__ import absolute_import

import six
import unittest
from mock import patch
from nacl import secret, encoding

from eduid_common.api.testing import EtcdTemporaryInstance
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.config.parsers import decorators
from eduid_common.config.idp import IdPConfig


class TestTypedConfig(unittest.TestCase):

    def setUp(self):
        self.etcd_instance = EtcdTemporaryInstance()

        self.ns = '/test/'
        self.parser = EtcdConfigParser(namespace=self.ns, host=self.etcd_instance.host, port=self.etcd_instance.port)

    def tearDown(self):
        self.etcd_instance.shutdown()

    def test_write(self):

        config = {
            'test': {
                'debug': True,
            }
        }

        self.parser.write_configuration(config)

        self.assertEqual(self.parser.get('my_bool'), True)

    def test_read(self):

        config = {
            'test': {
                'debug': True,
            }
        }

        self.parser.write_configuration(config)
        read_config = self.parser.read_configuration()

        self.assertEqual(config['test'], read_config)
