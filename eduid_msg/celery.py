from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init

from eduid_am.config import read_configuration


celery = Celery('eduid_msg.celery', include=['eduid_msg.tasks'])


# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    settings = read_configuration()
    conf.update(settings)


def get_sms_relay(celery_app):
    return celery_app.tasks['eduid_msg.tasks.sms_relay']

