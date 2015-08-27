from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init

from eduid_am.config import read_configuration
from eduid_userdb.db import MongoDB


celery = Celery('eduid_am.celery', backend='amqp', include=['eduid_am.tasks'])
celery.conf.update(read_configuration())


# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    settings = read_configuration()
    conf.update(settings)
    setup_indexes(settings, 'attributes')


def setup_indexes(settings, collection):
    """
    Ensure that indexes in eduid_am.attributes collection are correctly setup.
    To update an index add a new item in indexes and remove the previous version.
    """
    indexes = {
        # 'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}
        # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
        'mail-index-v2': {'key': [('mail', 1)], 'unique': True, 'sparse': True},
        'eppn-index-v1': {'key': [('eduPersonPrincipalName', 1)], 'unique': True},
        'norEduPersonNIN-index-v2': {'key': [('norEduPersonNIN', 1)], 'unique': True, 'sparse': True},
        'mobile-index-v1': {'key': [('mobile.mobile', 1), ('mobile.verified', 1)]},
        'mailAliases-index-v1': {'key': [('mailAliases.email', 1), ('mailAliases.verified', 1)]}
    }
    db = UserDB(settings.get('MONGO_URI', DEFAULT_MONGODB_URI), collection=collection)
    db.setup_indexes(indexes)


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
    assert isinstance(am, eduid_am.tasks.AttributeManager)  # a type hint for IDEs and analyzers
    return am
