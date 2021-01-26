# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
from typing import Any, Dict, Type

from eduid_common.config.base import BaseConfig, CommonConfig
from eduid_common.config.exceptions import BadConfiguration
from eduid_common.config.parsers.etcd import EtcdConfigParser


def get_worker_config(name: str, config_class: Type[CommonConfig] = BaseConfig) -> CommonConfig:
    """
    Load configuration for a worker.

    Currently, this means loading it from etcd.

    :param name: Worker name

    :return: Configuration
    """
    cfg: Dict[str, Any] = {}
    app_etcd_namespace = os.environ.get('EDUID_CONFIG_NS', '/eduid/worker/{}/'.format(name))
    common_parser = EtcdConfigParser('/eduid/worker/common/', silent=True)
    app_parser = EtcdConfigParser(app_etcd_namespace, silent=True)
    cfg.update(common_parser.read_configuration())
    cfg.update(app_parser.read_configuration())
    config = config_class(**cfg)
    if config.celery.broker_url == '':
        raise BadConfiguration('broker_url for celery is missing')
    return config
