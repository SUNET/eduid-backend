# -*- coding: utf-8 -*-

import os
import unittest

from eduid.common.config.parsers import _choose_parser
from eduid.common.config.parsers.etcd import EtcdConfigParser
from eduid.common.config.parsers.yaml_parser import YamlConfigParser

__author__ = 'lundberg'


class TestInitConfig(unittest.TestCase):
    def tearDown(self):
        os.environ.clear()

    def test_EtcdConfigParser(self):
        os.environ['EDUID_CONFIG_NS'] = '/test/ns/'
        parser = _choose_parser(app_name='app', ns='test')
        self.assertIsInstance(parser, EtcdConfigParser)

    def test_YamlConfigParser(self):
        os.environ['EDUID_CONFIG_NS'] = '/test/ns/'
        os.environ['EDUID_CONFIG_YAML'] = '/config.yaml'
        parser = _choose_parser(app_name='app', ns='test')
        self.assertIsInstance(parser, YamlConfigParser)
