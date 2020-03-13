# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os

from eduid_common.config.parsers.exceptions import ParserException

try:
    # Do not force applications that does not use EtcdConfigParser to have yaml and etcd installed
    from eduid_common.config.parsers.etcd import EtcdConfigParser
except ImportError:
    EtcdConfigParser = None  # type: ignore

__author__ = 'lundberg'


class ConfigParser(object):
    """
    Load config based on environment variable
    """

    def __new__(cls, **kwargs):
        """
        Load the config parser based on environment variable EDUID_CONFIG_NS
        """
        ns = os.environ.get('EDUID_CONFIG_NS')
        if ns:
            if EtcdConfigParser is None:
                raise ParserException('EtcdConfigParser could not be imported')
            return EtcdConfigParser(ns, **kwargs)
        raise ParserException('No environment variable for config initialization found')

    def read_configuration(self):
        """
        :return: Configuration
        :rtype: dict
        """
        raise NotImplementedError()
