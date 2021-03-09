from eduid.common.config.workers import MsgConfig
from eduid.common.rpc.celery import init_celery
from eduid.common.rpc.worker import get_worker_config

import eduid.workers.msg.common as common

worker_config: MsgConfig = MsgConfig(app_name='app_name_NOT_SET')

if common.celery is None:
    worker_config = get_worker_config('msg', config_class=MsgConfig)
    celery = init_celery('eduid_msg', config=worker_config.celery, include=['eduid_msg.tasks'])

    # When Celery starts the worker, it expects there to be a 'celery' in the module it loads,
    # but our tasks expect to find the Celery instance in eduid.workers.am.common.celery - so copy it there
    common.celery = celery
