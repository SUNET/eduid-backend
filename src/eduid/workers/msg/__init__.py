"""
The eduID messaging package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
from typing import Optional, TYPE_CHECKING

from celery import Celery

from eduid.common.config.base import CeleryConfig
from eduid.common.rpc.celery import init_celery as _init_celery

import eduid.workers.msg.common as common

if TYPE_CHECKING:
    from eduid.workers.msg.tasks import MessageRelay


def init_app(config: Optional[CeleryConfig]) -> Celery:
    common.celery = _init_celery('eduid_msg', config)
    return common.celery


def get_message_relay(celery_app: Celery) -> 'MessageRelay':
    """
    Function that return a celery task list.
    """
    if common.celery is None:
        raise RuntimeError('Must call init_app before get_message_relay')
    # It is important to not import eduid.workers.am.tasks before the Celery config has been set up
    # (done by caller before calling this function). Since Celery uses decorators, it will
    # have instantiated AttributeManagers without the right config if the import is done prior
    # to the Celery app configuration.
    import eduid.workers.msg.tasks

    msg = celery_app.tasks['eduid.workers.msg.tasks.send_message']
    assert isinstance(msg, eduid.workers.msg.tasks.MessageRelay)  # a type hint for IDEs and analyzers
    return msg



def get_mail_relay(celery_app: Celery) -> 'MessageRelay':
    """
    Function that return a celery task list.
    """
    if common.celery is None:
        raise RuntimeError('Must call init_app before get_mail_relay')
    # It is important to not import eduid.workers.am.tasks before the Celery config has been set up
    # (done by caller before calling this function). Since Celery uses decorators, it will
    # have instantiated AttributeManagers without the right config if the import is done prior
    # to the Celery app configuration.
    import eduid.workers.msg.tasks

    msg = celery_app.tasks['eduid.workers.msg.tasks.sendmail']
    assert isinstance(msg, eduid.workers.msg.tasks.MessageRelay)  # a type hint for IDEs and analyzers
    return msg
