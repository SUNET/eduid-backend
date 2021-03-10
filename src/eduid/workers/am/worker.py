import sys

from eduid.common.config.workers import AmConfig
from eduid.common.rpc.worker import get_worker_config
from eduid.userdb import UserDB
from eduid.workers.am.common import AmWorkerSingleton

# This is the Celery worker's entrypoint module - should not be imported anywhere!
if 'celery' not in sys.argv[0]:
    raise RuntimeError('Do not import the Celery worker entrypoint module')

app = AmWorkerSingleton.celery

AmWorkerSingleton.update_config(get_worker_config('am', config_class=AmConfig))



def setup_indexes(db_uri, db_name, collection):
    """
    Ensure that indexes in eduid.workers.am.attributes collection are correctly setup.
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


if AmWorkerSingleton.am_config.mongo_uri:
    # TODO: Try and move this to the userdb AmDb init instead - only run if writes are allowed?
    setup_indexes(AmWorkerSingleton.am_config.mongo_uri, 'eduid_am', 'attributes')
