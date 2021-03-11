import os
import unittest
from pathlib import PurePath

import pytest
from pydantic import ValidationError

from eduid.common.config.base import RootConfig
from eduid.common.config.parsers import load_config

__author__ = 'ft'


class TestConfig(RootConfig):
    foo: str
    number: int
    only_default: int = 19


# TODO: test decryption


class TestInitConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.data_dir = PurePath(__file__).with_name('data')

    def tearDown(self):
        os.environ.clear()

    def test_YamlConfig(self):
        os.environ['EDUID_CONFIG_NS'] = '/eduid/test/app_one'
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/test/common'
        os.environ['EDUID_CONFIG_YAML'] = str(self.data_dir / 'test.yaml')

        config_one = load_config(typ=TestConfig, ns='test', app_name='app_one')
        assert config_one.debug
        assert config_one.app_name == 'test_app_name'
        assert config_one.foo == 'bar'
        assert config_one.number == 9
        assert config_one.only_default == 19

        os.environ['EDUID_CONFIG_NS'] = '/eduid/test/app_two'

        config_two = load_config(typ=TestConfig, ns='test', app_name='app_two')
        assert config_two.debug
        assert config_two.app_name == 'app_two'
        assert config_two.foo == 'kaka'
        assert config_two.number == 10
        assert config_two.only_default == 19

    def test_YamlConfig_interpolation(self):
        os.environ['EDUID_CONFIG_NS'] = '/eduid/test/test_interpolation'
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/test/common'
        os.environ['EDUID_CONFIG_YAML'] = str(self.data_dir / 'test.yaml')

        config = load_config(typ=TestConfig, ns='test', app_name='test_interpolation')
        assert config.number == 3
        assert config.foo == 'hi world'

    def test_YamlConfig_missing_value(self):
        os.environ['EDUID_CONFIG_NS'] = '/eduid/test/test_missing_value'
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/test/common'
        os.environ['EDUID_CONFIG_YAML'] = str(self.data_dir / 'test.yaml')

        with pytest.raises(ValidationError) as exc_info:
            load_config(typ=TestConfig, ns='test', app_name='test_missing_value')

        assert exc_info.value.errors() == [{'loc': ('number',), 'msg': 'field required', 'type': 'value_error.missing'}]

    def test_YamlConfig_wrong_type(self):
        os.environ['EDUID_CONFIG_NS'] = '/eduid/test/test_wrong_type'
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/test/common'
        os.environ['EDUID_CONFIG_YAML'] = str(self.data_dir / 'test.yaml')

        with pytest.raises(ValidationError) as exc_info:
            load_config(typ=TestConfig, ns='test', app_name='test_wrong_type')

        assert exc_info.value.errors() == [
            {'loc': ('number',), 'msg': 'value is not a valid integer', 'type': 'type_error.integer'}
        ]

    def test_YamlConfig_unknown_data(self):
        """ Unknown data should not be rejected because it is an operational nightmare """
        os.environ['EDUID_CONFIG_NS'] = '/eduid/test/test_unknown_data'
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/test/common'
        os.environ['EDUID_CONFIG_YAML'] = str(self.data_dir / 'test.yaml')

        config = load_config(typ=TestConfig, ns='test', app_name='test_unknown_data')
        assert config.number == 0xFF
        assert config.foo == 'bar'

    def test_YamlConfig_mixed_case_keys(self):
        """ For legacy reasons, all keys should be lowercased """
        os.environ['EDUID_CONFIG_NS'] = '/eduid/test/test_mixed_case_keys'
        os.environ['EDUID_CONFIG_COMMON_NS'] = '/eduid/test/common'
        os.environ['EDUID_CONFIG_YAML'] = str(self.data_dir / 'test.yaml')

        config = load_config(typ=TestConfig, ns='test', app_name='test_mixed_case_keys')
        assert config.number == 1
        assert config.foo == 'bar'
        assert config.app_name == 'test_mixed_case_keys'
