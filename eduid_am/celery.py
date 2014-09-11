from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init

from eduid_am.config import read_configuration
from eduid_am.db import MongoDB, DEFAULT_MONGODB_URI


celery = Celery('eduid_am.celery', backend='amqp', include=['eduid_am.tasks'])


# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    settings = read_configuration()
    conf.update(settings)
    setup_indexes(settings)


def create_index(db, name, params):
    key = params['key']
    del params['key']
    params['name'] = name
    db.attributes.ensure_index(key, **params)


def setup_indexes(settings):
    """
    Ensure that indexes in eduid_am database are correctly setup.
    """
    indexes = {
        # 'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}
        # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
        'mail-index': {'key': [('mail', 1)], 'unique': True, 'sparse': True},
        'eppn-index': {'key': [('eduPersonPrincipalName', 1)], 'unique': True},
        'norEduPersonNIN-index': {'key': [('norEduPersonNIN', 1)], 'unique': True, 'sparse': True},
        'mobile-index': {'key': [('mobile.mobile', 1), ('mobile.verified', 1)]},
        'mailAliases-index': {'key': [('mailAliases.email', 1), ('mailAliases.verified', 1)]}
    }
    db_conn = MongoDB(settings.get('MONGO_URI', DEFAULT_MONGODB_URI))
    db = db_conn.get_database()
    current_indexes = db.attributes.index_information()
    for name, params in indexes.items():
        if name not in current_indexes:
            create_index(db, name, params)
        else:
            for key, value in params.items():
                if current_indexes[name].get(key) != value:
                    db.attributes.drop_index(name)
                    create_index(db, name, params)
                    break


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
    from eduid_am.tasks import AttributeManager
    assert isinstance(am, AttributeManager)  # a type hint for IDEs and analyzers
    return am
