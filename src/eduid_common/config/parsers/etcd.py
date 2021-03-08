# -*- coding: utf-8 -*-

from __future__ import absolute_import

import json
import logging
import os
from typing import Any, Mapping, Optional

import etcd

from eduid_common.config.parsers.base import BaseConfigParser
from eduid_common.config.parsers.decorators import decrypt, interpolate
from eduid_common.config.parsers.exceptions import ParserException

__author__ = 'lundberg'


class EtcdConfigParser(BaseConfigParser):
    def __init__(self, namespace: str, host: Optional[str] = None, port: Optional[int] = None, silent: bool = False):
        """
        :param namespace: etcd namespace to read or write, ex. /eduid/webapp/common/
        :param host: Optional etcd host
        :param port: Optional etcd port
        :param silent: set to `True` if you want to silently ignore etcd errors (such as EtcdConnectionFailed).
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

        self.silent = silent

        self.client = etcd.Client(host, port)

    def _fq_key(self, key):
        """
        :param key: Key to look up
        :type key: str | unicode

        :return: Fully qualified key, self.ns + key
        :rtype: str | unicode
        """
        return '{!s}{!s}'.format(self.ns, key)

    @interpolate
    @decrypt
    def read_configuration(self, path: str) -> Mapping[str, Any]:
        """
        :return: Configuration dict

        Recurse over keys in a given namespace and create a dict from the key-value pairs.

        Keys starting with var_ (var underscore) will be ignored in the final configuration but can still be used
        for interpolation.
        Values will be json encoded on write and json decoded on read.

        Ex.

        path = '/eduid/webapp/common/'

        Key and value in etcd:
        /eduid/webapp/common/saml_config -> "{xmlsec_binary': '/usr/bin/xmlsec1'}"
        /eduid/webapp/common/var_password -> "secret"
        /eduid/webapp/common/basic_auth -> "user:$VAR_PASSWORD@localost"

        This will return:
        {
            'SAML_CONFIG': {
                'xmlsec_binary': '/usr/bin/xmlsec1'
            },
            'BASIC_AUTH': 'user:secret@localhost'
        }
        """
        _path = path.lower()
        if not _path.startswith('/'):
            raise ParserException(f'Path {_path} has to start with a slash')
        if not _path.endswith('/'):
            # Be nice and fix it
            _path = f'{_path}/'

        config = {}
        try:
            for child in self.client.read(_path, recursive=True).children:
                # Remove everything but the last element of the key
                key = child.key.split('/')[-1]
                # Load etcd string with json to handle complex structures
                config[key] = json.loads(child.value)
        except (etcd.EtcdKeyNotFound, etcd.EtcdConnectionFailed) as e:
            logging.info(e)
            if not self.silent:
                raise e
        return config

    def get(self, key: str) -> Any:
        """
        :param key: Key to look up

        :return: JSON loaded value
        """
        value = self.client.read(self._fq_key(key)).value
        return json.loads(value)

    def set(self, key: str, value: Any) -> None:
        json_value = json.dumps(value)
        self.client.write(self._fq_key(key), json_value)

    def write_configuration(self, config: Mapping[str, Any]) -> None:
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


        :param this_config: Config dict
        :type this_config: dict
        """
        # Remove first and last slash and create key hierarchy
        ns_keys = self.ns.lstrip('/').rstrip('/').split('/')
        this_config = dict(config)  # do not modify callers data
        # Traverse the dict using the list of keys from the namespace
        try:
            for key in ns_keys:
                this_config = this_config[key]
        except KeyError as e:
            raise ParserException(f'Namespace does not match configuration structure: {e}')
        # Write keys and values to etcd
        for key, value in this_config.items():
            self.set(key, value)

    def write_configuration_from_yaml_file(self, file_path: str) -> None:
        """
        :param file_path: Full path to a file with yaml content
        """
        # import here since most users of this module do not write config to files and
        # thus might not need a yaml dependency
        import yaml

        with open(file_path) as f:
            config = yaml.safe_load(f)
            if not config:
                raise ParserException('No YAML found in {!s}'.format(file_path))
            self.write_configuration(config)
