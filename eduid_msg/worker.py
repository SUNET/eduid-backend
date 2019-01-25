from eduid_common.rpc.worker import get_worker_config
from eduid_common.rpc.celery import init_celery

import eduid_msg.common as common

worker_config = {}

if common.celery is None:
    worker_config = get_worker_config('msg')
    celery = init_celery('eduid_msg', config=worker_config['CELERY'], include=['eduid_msg.tasks'])

    # When Celery starts the worker, it expects there to be a 'celery' in the module it loads,
    # but our tasks expect to find the Celery instance in eduid_am.common.celery - so copy it there
    common.celery = celery
