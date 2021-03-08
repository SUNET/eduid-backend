"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
from typing import Optional

from celery import Celery

from eduid_common.config.base import CeleryConfig
from eduid_common.rpc.celery import init_celery

import eduid_am.common as common


def init_app(config: Optional[CeleryConfig]) -> Celery:
    common.celery = init_celery('am', config)
    return common.celery


def get_attribute_manager(celery_app):
    """
    Get an AttributeManager Celery task instance.

    :param celery_app: ???
    :return: AttributeManager
    :rtype: AttributeManager
    """
    if common.celery is None:
        raise RuntimeError('Must call init_app before get_attribute_manager')
    # It is important to not import eduid_am.tasks before the Celery config has been set up
    # (done by caller before calling this function). Since Celery uses decorators, it will
    # have instantiated AttributeManagers without the right config if the import is done prior
    # to the Celery app configuration.
    import eduid_am.tasks

    am = celery_app.tasks['eduid_am.tasks.update_attributes']
    assert isinstance(am, eduid_am.tasks.AttributeManager)  # a type hint for IDEs and analyzers
    return am
