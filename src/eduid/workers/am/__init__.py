"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
from typing import Optional, TYPE_CHECKING

from celery import Celery

from eduid.common.config.base import CeleryConfig
from eduid.common.rpc.celery import init_celery

import eduid.workers.am.common as common

if TYPE_CHECKING:
    from eduid.workers.am.tasks import AttributeManager


def init_app(config: Optional[CeleryConfig]) -> Celery:
    common.celery = init_celery('am', config)
    return common.celery


def Xget_attribute_manager(celery_app: Celery) -> 'AttributeManager':
    """
    Get an AttributeManager Celery task instance.

    :param celery_app: ???
    :return: AttributeManager
    :rtype: AttributeManager
    """
    if common.celery is None:
        raise RuntimeError('Must call init_app before get_attribute_manager')
    # It is important to not import eduid.workers.am.tasks before the Celery config has been set up
    # (done by caller before calling this function). Since Celery uses decorators, it will
    # have instantiated AttributeManagers without the right config if the import is done prior
    # to the Celery app configuration.
    import eduid.workers.am.tasks

    am = celery_app.tasks['eduid.workers.am.tasks.update_attributes']
    assert isinstance(am, eduid.workers.am.tasks.AttributeManager)  # a type hint for IDEs and analyzers
    return am
