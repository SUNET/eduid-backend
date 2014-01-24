from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init

from eduid_am.config import read_configuration
from eduid_am.db import MongoDB, DEFAULT_MONGODB_URI
from eduid_am.tasks import AttributeManager


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
    db.attributes.ensure_index([('mailAliases.email', 1),
                                ('mailAliases.verified', 1)],
                               name='mailAliases-index')


def get_attribute_manager(celery_app):
    """
    Get an AttributeManager Celery task instance.

    :param celery_app: ???
    :return: AttributeManager
    :rtype: AttributeManager()
    """
    # without this import, celery suddenly says NotRegistered about update_attributes
    import eduid_am.tasks
    am = celery_app.tasks['eduid_am.tasks.update_attributes']
    assert isinstance(am, AttributeManager)  # a type hint for IDEs and analyzers
    return am
