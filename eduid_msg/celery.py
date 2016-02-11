"""
This module is a wrapper for celery initiation.
"""
from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init

from eduid_common.config.parsers import IniConfigParser

DEFAULT_CONFIG_FILE_NAME = 'eduid_msg.ini'
DEFAULT_CONFIG_ENV_VAR = 'EDUID_MSG_CONFIG'

config_parser = IniConfigParser(DEFAULT_CONFIG_FILE_NAME, DEFAULT_CONFIG_ENV_VAR)

celery = Celery('eduid_msg.celery', include=['eduid_msg.tasks'])
celery.conf.update(config_parser.read_configuration())


# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    """
    Function to setup celery.
    """
    pass  # If we need to do anything on connect later


def get_message_relay(celery_app):
    """
    Function that return a celery task list.
    """
    return celery_app.tasks['eduid_msg.tasks.send_message']

