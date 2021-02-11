import eduid_am.common as common
from eduid_common.config.workers import AmConfig
from eduid_common.rpc.celery import init_celery
from eduid_common.rpc.worker import get_worker_config
from eduid_userdb import UserDB

worker_config = AmConfig(app_name='app_name_NOT_SET')

if common.celery is None:
    worker_config = get_worker_config('am', config_class=AmConfig)
    celery = init_celery('eduid_am', config=worker_config.celery, include=['eduid_am.tasks'])

    # When Celery starts the worker, it expects there to be a 'celery' in the module it loads,
    # but our tasks expect to find the Celery instance in common.celery - so copy it there
    common.celery = celery


def setup_indexes(db_uri, db_name, collection):
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
        'mailAliases-index-v1': {'key': [('mailAliases.email', 1), ('mailAliases.verified', 1)]},
    }
    userdb = UserDB(db_uri, db_name=db_name, collection=collection)
    userdb.setup_indexes(indexes)
    userdb.close()


if worker_config.mongo_uri:
    setup_indexes(worker_config.mongo_uri, 'eduid_am', 'attributes')
