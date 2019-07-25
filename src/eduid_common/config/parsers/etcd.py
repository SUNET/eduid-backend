# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import etcd
import json
import logging

from eduid_common.config.parsers.decorators import decrypt, interpolate
from eduid_common.config.parsers.exceptions import ParserException

__author__ = 'lundberg'


class EtcdConfigParser(object):

    def __init__(self, namespace, host=None, port=None):
        """
        :param namespace: etcd namespace to read or write, ex. /eduid/webapp/common/
        :param host: Optional etcd host
        :param port: Optional etcd port

        :type host: str | unicode
        :type namespace: str | unicode
        :type port: int

        :return: EtcdConfigParser object
        :rtype: EtcdConfigParser
        """
        self.ns = namespace.lower()
        if not self.ns.startswith('/'):
            raise ParserException('Namespace {!s} has to start and end with a \"/\" character'.format(namespace))
        if not self.ns.endswith('/'):
            # Be nice and fix it
            self.ns = '{}/'.format(self.ns)

        if not host:
            host = os.environ.get('ETCD_HOST', '127.0.0.1')
        if not port:
            port = int(os.environ.get('ETCD_PORT', '2379'))
        self.client = etcd.Client(host, port)

    def _fq_key(self, key):
        """
        :param key: Key to look up
        :type key: str | unicode

        :return: Fully qualified key, self.ns + key
        :rtype: str | unicode
        """
        return '{!s}{!s}'.format(self.ns, key.lower())

    @interpolate
    @decrypt
    def read_configuration(self, silent=False):
        """
        :param silent: set to `True` if you want silent failure for missing keys.
        :type silent: bool
        :return: Configuration dict
        :rtype: dict

        Recurse over keys in a given namespace and create a dict from the key-value pairs.

        Values will be json encoded on write and json decoded on read.

        Ex.

        ns = '/eduid/webapp/common/'

        Key and value in etcd:
        /eduid/webapp/common/saml_config -> "{xmlsec_binary': '/usr/bin/xmlsec1'}"

        This will return:
        {
            'SAML_CONFIG': {
                'xmlsec_binary': '/usr/bin/xmlsec1'
            }
        }

        :return: Config dict
        :rtype: dict
        """
        config = {}
        try:
            for child in self.client.read(self.ns, recursive=True).children:
                # Remove namespace
                key = child.key.split('/')[-1]
                # Load etcd string with json to handle complex structures
                config[key] = json.loads(child.value)
        except (etcd.EtcdKeyNotFound, etcd.EtcdConnectionFailed) as e:
            logging.info(e)
            if not silent:
                raise e
        return config

    def get(self, key):
        """
        :param key: Key to look up
        :type key: str | unicode

        :return: JSON loaded value
        :rtype: str | unicode | int | float | list | dict
        """
        value = self.client.read(self._fq_key(key)).value
        return json.loads(value)

    def set(self, key, value):
        json_value = json.dumps(value)
        self.client.write(self._fq_key(key), json_value)

    def write_configuration(self, config):
        """
        Transforms a dict using the namespace to key-value pairs that get written to
        etcd in the set namespace.

        Values will be json encoded on write and json decoded on read.

        Ex.

        ns = '/eduid/webapp/common/'

        config = {
            'eduid': {
                'webapp': {
                    'common': {
                        'SAML_CONFIG': {
                            'xmlsec_binary': '/usr/bin/xmlsec1'
                        }
                    }
                }
            }
        }

        will end up in etcd as:

        /eduid/webapp/common/saml_config -> "{xmlsec_binary': '/usr/bin/xmlsec1'}"


        :param config: Config dict
        :type config: dict
        """
        # Remove first and last slash and create key hierarchy
        ns_keys = self.ns.lstrip('/').rstrip('/').split('/')
        # Traverse the dict using the list of keys from the namespace
        try:
            for key in ns_keys:
                config = config[key]
        except KeyError as e:
            raise ParserException('Namespace does not match configuration structure: {!s}'.format(e))
        # Write keys and values to etcd
        for key, value in config.items():
            self.set(key, value)

    def write_configuration_from_yaml_file(self, file_path):
        """
        :param file_path: Full path to a file with yaml content

        :type file_path: str | unicode
        """
        # import here since most users of this module do not write config to files and
        # thus might not need a yaml dependency
        import yaml
        with open(file_path) as f:
            config = yaml.safe_load(f)
            if not config:
                raise ParserException('No YAML found in {!s}'.format(file_path))
            self.write_configuration(config)
