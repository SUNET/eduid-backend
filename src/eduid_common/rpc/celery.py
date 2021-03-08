# -*- coding: utf-8 -*-
from typing import Optional

from celery import Celery

from eduid_common.config.base import CeleryConfig


def init_celery(name: str, config: Optional[CeleryConfig], **kwargs) -> Celery:
    """
    Initialize Celery.

    :param name: Worker name
    :param config: Celery configuration
    :param kwargs: Extra arguments passed to Celery

    :return: Celery instance
    """
    if config is not None:
        kwargs['config_source'] = config.dict()

    return Celery(name, **kwargs)
