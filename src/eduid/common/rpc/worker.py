# -*- coding: utf-8 -*-
from typing import Type, TypeVar

from eduid.common.config import WorkerConfig
from eduid.common.config.exceptions import BadConfiguration
from eduid.common.config.parsers import load_config

TWorkerConfigSubclass = TypeVar('TWorkerConfigSubclass', bound=WorkerConfig)


def get_worker_config(name: str, config_class: Type[TWorkerConfigSubclass]) -> TWorkerConfigSubclass:
    """
    Load configuration for a worker.

    :param name: Worker name
    :param config_class: What kind of configuration to initialise

    :return: Configuration
    """
    config = load_config(typ=config_class, app_name=name, ns='worker')
    if not config.celery.broker_url:
        raise BadConfiguration('broker_url for celery is missing')
    return config
