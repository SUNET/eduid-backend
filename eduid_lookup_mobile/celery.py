from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init
from eduid_lookup_mobile import config

app = Celery('eduid_lookup_mobile.celery', include=['eduid_lookup_mobile.tasks'], backend='amqp')

# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    settings = config.read_configuration()
    conf.update(settings)