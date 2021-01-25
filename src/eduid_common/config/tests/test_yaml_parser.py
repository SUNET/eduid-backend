import os
import unittest
from pathlib import PurePath

from eduid_common.config.base import RootConfig
from eduid_common.config.parsers import load_config

__author__ = 'ft'


class TestConfig(RootConfig):
    foo: str
    number: int
    only_default: int = 19


class TestInitConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.data_dir = PurePath(__file__).with_name('data')

    def tearDown(self):
        os.environ.clear()

    def test_YamlConfig(self):
        os.environ['EDUID_CONFIG_NS'] = '/test/'
        os.environ['EDUID_CONFIG_YAML'] = str(self.data_dir / 'test.yaml')

        config_one = load_config(typ=TestConfig, ns='test', app_name='app_one')
        assert config_one.debug
        assert config_one.app_name == 'test_app_name'
        assert config_one.foo == 'bar'
        assert config_one.number == 9
        assert config_one.only_default == 19

        config_two = load_config(typ=TestConfig, ns='test', app_name='app_two')
        assert config_two.debug
        assert config_two.app_name == 'app_two'
        assert config_two.foo == 'kaka'
        assert config_two.number == 10
        assert config_two.only_default == 19
