# -*- coding: utf-8 -*-

from __future__ import absolute_import

from celery import Celery


def init_celery(name, config=None, **kwargs):
    """
    Initialize Celery.

    :param name: Worker name
    :param config: Celery configuration
    :param kwargs: Extra arguments passed to Celery

    :type name: str
    :type config: dict
    :type init_callable: callable or None

    :return: Celery instance
    :rtype: celery.Celery
    """
    if config is not None:
        kwargs['config_source'] = config

    return Celery(name, **kwargs)
