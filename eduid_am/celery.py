from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init

from eduid_am.config import read_configuration
from eduid_am.db import MongoDB, DEFAULT_MONGODB_URI


celery = Celery('eduid_am.celery', include=['eduid_am.tasks'])


# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    settings = read_configuration()
    conf.update(settings)

    db_conn = MongoDB(settings.get('MONGO_URI', DEFAULT_MONGODB_URI))
    db = db_conn.get_database()
    db.attributes.ensure_index('email', name='email-index')
    db.attributes.ensure_index([('norEduPersonNIN.norEduPersonNIN', 1),
                                ('norEduPersonNIN.verified', 1),
                                ('norEduPersonNIN.status', 1)],
                               name='norEduPersonNIN-index')
    db.attributes.ensure_index([('mobile.mobile', 1),
                                ('mobile.verified', 1)],
                               name='mobile-index')


def get_attribute_manager(celery_app):
    return celery_app.tasks['eduid_am.tasks.update_attributes']
