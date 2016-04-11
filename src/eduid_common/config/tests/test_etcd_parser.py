# -*- coding: utf-8 -*-

import unittest
from eduid_common.api.testing import EtcdTemporaryInstance

from eduid_common.config.parsers import EtcdConfigParser

__author__ = 'lundberg'


class TestEtcdParser(unittest.TestCase):

    def setUp(self):
        self.etcd_instance = EtcdTemporaryInstance()

        self.ns = '/test/'
        self.parser = EtcdConfigParser(namespace=self.ns, host=self.etcd_instance.host, port=self.etcd_instance.port)

    def tearDown(self):
        self.etcd_instance.shutdown()

    def test_write(self):

        config = {
            'test': {
                'MY_BOOL': True,
                'MY_STRING': 'A value',
                'MY_LIST': ['One', 'Two', 3],
                'MY_DICT': {'A': 'B'}
            }
        }

        self.parser.write_configuration(config)

        self.assertEqual(self.parser.get('MY_BOOL'), True)
        self.assertEqual(self.parser.get('MY_STRING'), 'A value')
        self.assertEqual(self.parser.get('MY_LIST'), ['One', 'Two', 3])
        self.assertEqual(self.parser.get('MY_DICT'), {'A': 'B'})

    def test_read(self):

        config = {
            'test': {
                'MY_BOOL': True,
                'MY_STRING': 'A value',
                'MY_LIST': ['One', 'Two', 3],
                'MY_DICT': {'A': 'B'}
            }
        }

        self.parser.write_configuration(config)
        read_config = self.parser.read_configuration()

        self.assertEqual(config['test'], read_config)

    def test_set_get(self):

        self.parser.set('MY_SET_KEY', 'a nice value')
        self.assertEqual(self.parser.get('MY_SET_KEY'), 'a nice value')

        read_config = self.parser.read_configuration()
        self.assertEqual({'MY_SET_KEY': 'a nice value'}, read_config)

    def test_uppercase(self):

        config = {
            'test': {
                'my_bool': True,
                'my_string': 'A value',
                'my_list': ['One', 'Two', 3],
                'my_dict': {'A': 'B'}
            }
        }

        self.parser.write_configuration(config)
        read_config = self.parser.read_configuration()
        for key in config['test'].keys():
            self.assertIn(key.upper(), read_config.keys())

        self.parser.set('my_set_key', 'a nice value')
        self.assertEqual(self.parser.get('MY_SET_KEY'), 'a nice value')
