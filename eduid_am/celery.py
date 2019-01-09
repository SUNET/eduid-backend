from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_init

from eduid_userdb import UserDB
from eduid_common.config.parsers.ini import IniConfigParser

config_parser = IniConfigParser('eduid_am.ini', 'EDUID_AM_CONFIG')
# Make action_plugins be parsed as a list (default: []), just like celery_accept_content
config_parser.known_special_keys['action_plugins'] = (config_parser.read_list, [])

celery = Celery('eduid_am.celery', include=['eduid_am.tasks'])
celery.conf.update(config_parser.read_configuration())


# This signal is only emited when run as a worker
@celeryd_init.connect
def setup_celeryd(sender, conf, **kwargs):
    setup_indexes('eduid_am', 'attributes')


def setup_indexes(db_name, collection):
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
    userdb = UserDB(celery.conf.get('MONGO_URI'), db_name=db_name, collection=collection)
    userdb.setup_indexes(indexes)


def get_attribute_manager(celery_app):
    """
    Get an AttributeManager Celery task instance.

    :param celery_app: ???
    :return: AttributeManager
    :rtype: AttributeManager
    """
    # It is important to not import eduid_am.tasks before the Celery config has been set up
    # (done by caller before calling this function). Since Celery uses decorators, it will
    # have instantiated AttributeManagers without the right config the import is done prior
    # to the Celery app configuration.
    import eduid_am.tasks
    am = celery_app.tasks['eduid_am.tasks.update_attributes']
    assert isinstance(am, eduid_am.tasks.AttributeManager)  # a type hint for IDEs and analyzers
    return am
