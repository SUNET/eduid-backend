# -*- coding: utf-8 -*-

import os
import unittest

from eduid_common.config.parsers import ConfigParser
from eduid_common.config.parsers.etcd import EtcdConfigParser

__author__ = 'lundberg'


class TestEtcdParser(unittest.TestCase):
    def tearDown(self):
        os.environ.clear()

    def test_EtcdConfigParser(self):
        os.environ.setdefault('EDUID_CONFIG_NS', '/test/ns/')
        parser = ConfigParser()
        self.assertIsInstance(parser, EtcdConfigParser)
