# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
from typing import Type, Dict, Any, cast

from eduid_common.config.exceptions import BadConfiguration
from eduid_common.config.parsers.etcd import EtcdConfigParser
from eduid_common.config.base import CommonConfig, BaseConfig
from eduid_common.config.workers import AmConfig, MsgConfig, MobConfig


def get_worker_config(name: str, config_class: Type[CommonConfig] = BaseConfig) -> CommonConfig:
    """
    Load configuration for a worker.

    Currently, this means loading it from etcd.

    :param name: Worker name

    :return: Configuration
    :rtype: dict
    """
    cfg: Dict[str, Any] = {}
    app_etcd_namespace = os.environ.get('EDUID_CONFIG_NS', '/eduid/worker/{}/'.format(name))
    common_parser = EtcdConfigParser('/eduid/worker/common/')
    app_parser = EtcdConfigParser(app_etcd_namespace)
    cfg.update(common_parser.read_configuration(silent=True))
    cfg.update(app_parser.read_configuration(silent=True))
    config = config_class(**cfg)
    if config.celery.broker_url == '':
        raise BadConfiguration('broker_url for celery is missing')
    return config
