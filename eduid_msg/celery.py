"""
This module is a wrapper for celery initiation.
"""
from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init

from eduid_msg.config import read_configuration

celery = Celery('eduid_msg.celery', backend='amqp', include=['eduid_msg.tasks'])

# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    """
    Function to setup celery.
    """
    settings = read_configuration()
    conf.update(settings)


def get_message_relay(celery_app):
    """
    Function that return a celery task list.
    """
    return celery_app.tasks['eduid_msg.tasks.send_message', 'eduid_msg.tasks.is_reachable']

