# -*- coding: utf-8 -*-

from __future__ import absolute_import

import six
import unittest
from mock import patch
from nacl import secret, encoding

from eduid_common.api.testing import EtcdTemporaryInstance
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.config.parsers import decorators

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
                'my_bool': True,
                'my_string': 'A value',
                'my_list': ['One', 'Two', 3],
                'my_dict': {'A': 'B'},
                'var_ignore_me': 'Do not mind me'
            }
        }

        self.parser.write_configuration(config)

        self.assertEqual(self.parser.get('MY_BOOL'), True)
        self.assertEqual(self.parser.get('MY_STRING'), 'A value')
        self.assertEqual(self.parser.get('MY_LIST'), ['One', 'Two', 3])
        self.assertEqual(self.parser.get('MY_DICT'), {'A': 'B'})
        self.assertEqual(self.parser.get('VAR_IGNORE_ME'), 'Do not mind me')

    def test_read(self):

        config = {
            'test': {
                'my_bool': True,
                'my_string': 'A value',
                'my_list': ['One', 'Two', 3],
                'my_dict': {'A': 'B'},
                'var_ignore_me': 'Do not mind me'
            }
        }
        test_key = {
                'MY_BOOL': True,
                'MY_STRING': 'A value',
                'MY_LIST': ['One', 'Two', 3],
                'MY_DICT': {'A': 'B'}
            }

        self.parser.write_configuration(config)
        read_config = self.parser.read_configuration()

        self.assertEqual(test_key, read_config)

    def test_read_uc(self):

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

        self.parser.set('my_set_key', 'a nice value')
        self.assertEqual(self.parser.get('MY_SET_KEY'), 'a nice value')

        read_config = self.parser.read_configuration()
        self.assertEqual({'MY_SET_KEY': 'a nice value'}, read_config)

    @patch('eduid_common.config.parsers.decorators.read_secret_key')
    def test_decrypt(self, mock_read_secret_key):
        mock_read_secret_key.return_value = bytes(b'A'*secret.SecretBox.KEY_SIZE)

        box = secret.SecretBox(decorators.read_secret_key('test'))

        secret_value = [{
            'key_name': 'test',
            'value': bytes(box.encrypt(b'a nice value', encoder=encoding.URLSafeBase64Encoder)).decode('ascii')
        }]
        self.parser.set('my_set_key_encrypted', secret_value)
        self.parser.set('my_other_set_key', 'another nice value')

        read_config = self.parser.read_configuration()
        self.assertEqual({u'MY_SET_KEY': u'a nice value', u'MY_OTHER_SET_KEY': u'another nice value'}, read_config)
        self.assertIsInstance(read_config['MY_SET_KEY'], str)

    @patch('eduid_common.config.parsers.decorators.read_secret_key')
    def test_decrypt_non_ascii(self, mock_read_secret_key):
        mock_read_secret_key.return_value = bytes(b'A'*secret.SecretBox.KEY_SIZE)

        box = secret.SecretBox(decorators.read_secret_key('test'))

        the_value = 'a nåjs väljö'
        the_value = bytes(the_value, 'utf-8')

        secret_value = [{
            'key_name': 'test',
            'value': bytes(box.encrypt(the_value, encoder=encoding.URLSafeBase64Encoder)).decode('ascii')
        }]
        self.parser.set('my_set_key_encrypted', secret_value)
        self.parser.set('my_other_set_key', 'another nice value')

        read_config = self.parser.read_configuration()
        self.assertEqual({u'MY_SET_KEY': 'a nåjs väljö', u'MY_OTHER_SET_KEY': 'another nice value'}, read_config)
        self.assertIsInstance(read_config['MY_SET_KEY'], str)

    @patch('eduid_common.config.parsers.decorators.read_secret_key')
    def test_decrypt_multi_key(self, mock_read_secret_key):

        mock_read_secret_key.return_value = bytes(b'A'*secret.SecretBox.KEY_SIZE)

        box = secret.SecretBox(decorators.read_secret_key('test'))
        box2 = secret.SecretBox(bytes(b'B'*secret.SecretBox.KEY_SIZE))

        secret_value = [{
            'key_name': 'not_test',
            'value': bytes(box2.encrypt(b'a nice value', encoder=encoding.URLSafeBase64Encoder)).decode('ascii')
        }, {
            'key_name': 'test',
            'value': bytes(box.encrypt(b'a nice value', encoder=encoding.URLSafeBase64Encoder)).decode('ascii')
        }]
        self.parser.set('MY_SET_KEY_encrypted', secret_value)
        self.parser.set('MY_OTHER_SET_KEY', 'another nice value')

        read_config = self.parser.read_configuration()
        self.assertEqual({'MY_SET_KEY': 'a nice value', 'MY_OTHER_SET_KEY': 'another nice value'}, read_config)

    def test_interpolate(self):
        self.parser.set('my_set_key', '${MY_VALUE}')
        self.parser.set('my_value', 'a nice value')

        read_config = self.parser.read_configuration()
        self.assertEqual({'MY_SET_KEY': 'a nice value', 'MY_VALUE': 'a nice value'}, read_config)

    def test_interpolate_variable_key(self):
        self.parser.set('my_set_key', '${VAR_MY_VALUE}')
        self.parser.set('var_my_value', 'a nice value')
        self.assertEqual('a nice value', self.parser.get('VAR_MY_VALUE'))

        read_config = self.parser.read_configuration()
        self.assertEqual({'MY_SET_KEY': 'a nice value'}, read_config)

    def test_interpolate_missing_key(self):
        self.parser.set('my_set_key', '${my_value}')

        read_config = self.parser.read_configuration()
        self.assertEqual({'MY_SET_KEY': '${my_value}'}, read_config)

    def test_interpolate_complex_dict(self):
        self.parser.set('my_set_key', '${MY_VALUE}')
        self.parser.set('my_value', 'a nice value')
        self.parser.set('a_list', ['test', '${MY_VALUE}', {'a_dict_in_a_list': '${MY_VALUE}'}])
        self.parser.set('another_dict', {'string_in_sub_dict': '${MY_VALUE}',
                                         'a_dict_in_a_dict': {'another_key': '${MY_VALUE}'}})

        read_config = self.parser.read_configuration()

        expected = {
            'MY_SET_KEY': 'a nice value',
            'MY_VALUE': 'a nice value',
            'A_LIST': [
                'test',
                'a nice value',
                {'a_dict_in_a_list': 'a nice value'},
            ],
            'ANOTHER_DICT': {
                'string_in_sub_dict': 'a nice value',
                'a_dict_in_a_dict': {'another_key': 'a nice value'}
            }
        }
        self.assertEqual(expected, read_config)

    @patch('eduid_common.config.parsers.decorators.read_secret_key')
    def test_decrypt_interpolate(self, mock_read_secret_key):
        mock_read_secret_key.return_value = bytes(b'A'*secret.SecretBox.KEY_SIZE)

        box = secret.SecretBox(decorators.read_secret_key('test'))

        secret_value = [{
            'key_name': 'test',
            'value': bytes(box.encrypt(b'a secret value', encoder=encoding.URLSafeBase64Encoder)).decode('ascii')
        }]
        self.parser.set('my_secret_encrypted', secret_value)
        self.parser.set('my_other_set_key', '${MY_SECRET} is set here')

        read_config = self.parser.read_configuration()
        self.assertEqual({u'MY_SECRET': u'a secret value', u'MY_OTHER_SET_KEY': u'a secret value is set here'},
                         read_config)
