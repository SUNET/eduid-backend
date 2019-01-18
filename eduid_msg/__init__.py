"""
The eduID messaging package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
from __future__ import absolute_import

from eduid_common.rpc.celery import init_celery as _init_celery
import eduid_msg.common as common

def init_app(config):
    common.celery = _init_celery('eduid_msg', config)
    return common.celery


def get_message_relay(celery_app):
    """
    Function that return a celery task list.
    """
    return celery_app.tasks['eduid_msg.tasks.send_message']


def get_mail_relay(celery_app):
    """
    Function that return a celery task list.
    """
    return celery_app.tasks['eduid_msg.tasks.sendmail']

