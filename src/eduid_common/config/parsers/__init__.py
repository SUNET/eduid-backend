# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.config.parsers.base import ConfigParser
from eduid_common.config.parsers.ini import IniConfigParser
try:
    # Do not force applications that does not use EtcdConfigParser to have yaml and etcd installed
    from eduid_common.config.parsers.etcd import EtcdConfigParser
except ImportError:
    EtcdConfigParser = None

__author__ = 'lundberg'
