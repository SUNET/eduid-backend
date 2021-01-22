# -*- coding: utf-8 -*-

import os
import unittest

from eduid_common.config.base import BaseConfig
from eduid_common.config.parsers import init_config
from eduid_common.config.parsers.etcd import EtcdConfigParser

__author__ = 'lundberg'

from eduid_common.config.parsers.yaml import YamlConfigParser


class TestInitConfig(unittest.TestCase):
    def tearDown(self):
        os.environ.clear()

    def test_EtcdConfigParser(self):
        os.environ['EDUID_CONFIG_NS'] = '/test/ns/'
        parser = init_config(typ=BaseConfig, ns='test', app_name='app', return_parser=True)
        self.assertIsInstance(parser, EtcdConfigParser)

    def test_YamlConfigParser(self):
        os.environ['EDUID_CONFIG_NS'] = '/test/ns/'
        os.environ['EDUID_CONFIG_YAML'] = '/config.yaml'
        parser = init_config(typ=BaseConfig, ns='test', app_name='app', return_parser=True)
        self.assertIsInstance(parser, YamlConfigParser)
