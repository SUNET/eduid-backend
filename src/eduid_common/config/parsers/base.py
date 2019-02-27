# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os

from eduid_common.config.parsers.ini import IniConfigParser
try:
    # Do not force applications that does not use EtcdConfigParser to have yaml and etcd installed
    from eduid_common.config.parsers.etcd import EtcdConfigParser
except ImportError:
    EtcdConfigParser = None  # type: ignore
from eduid_common.config.parsers.exceptions import ParserException

__author__ = 'lundberg'


class ConfigParser(object):
    """
    Load config based on environment variable
    """

    def __new__(cls, **kwargs):
        """
        Load the type of config parser based on environment variables EDUID_CONFIG_NS or
        EDUID_INI_FILE_NAME.

        EDUID_CONFIG_NS initilizes EtcdConfigParser
        EDUID_CONFIG_FILE_NAME initializes IniConfigParser
        """
        ns = os.environ.get('EDUID_CONFIG_NS')
        ini_file_name = os.environ.get('EDUID_INI_FILE_NAME')
        if ns:
            if EtcdConfigParser is None:
                raise ParserException('EtcdConfigParser could not be imported')
            return EtcdConfigParser(ns, **kwargs)
        elif ini_file_name:
            return IniConfigParser(ini_file_name, **kwargs)
        raise ParserException('No environment variable for config initialization found')

    def read_configuration(self):
        """
        :return: Configuration
        :rtype: dict
        """
        raise NotImplementedError()
