from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init
from eduid_lookup_mobile import config

app = Celery('eduid_lookup_mobile.celery', include=['eduid_lookup_mobile.tasks'])
app.conf.update(config.read_configuration())


# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    pass  # If we need to do anything on connect later
