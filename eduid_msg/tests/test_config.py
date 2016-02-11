from unittest import TestCase
from eduid_common.config.parsers import IniConfigParser
import os
import pkg_resources


class TestConfig(TestCase):
    def setUp(self):
        data_dir = pkg_resources.resource_filename(__name__, 'data')
        self.config_file = os.path.join(data_dir, 'test.ini')
        os.environ['EDUID_MSG_CONFIG'] = self.config_file
        self.config_parser = IniConfigParser('', 'EDUID_MSG_CONFIG')

    def test_get_config_file(self):
        file = self.config_parser.get_config_file()
        self.assertEqual(file, self.config_file)

    def test_read_configuration(self):
        settings = self.config_parser.read_configuration()
        self.assertEqual(settings['SMS_ACC'], 'bla')
