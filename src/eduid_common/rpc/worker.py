# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os

from eduid_common.config.parsers.etcd import EtcdConfigParser


def get_worker_config(name):
    """
    Load configuration for a worker.

    Currently, this means loading it from etcd.

    :param name: Worker name
    :type name: str

    :return: Configuration
    :rtype: dict
    """
    cfg = {}
    app_etcd_namespace = os.environ.get('EDUID_CONFIG_NS', '/eduid/worker/{}/'.format(name))
    common_parser = EtcdConfigParser('/eduid/worker/common/')
    app_parser = EtcdConfigParser(app_etcd_namespace)
    cfg.update(common_parser.read_configuration(silent=True))
    cfg.update(app_parser.read_configuration(silent=True))
    return cfg
