from __future__ import absolute_import

from eduid_common.rpc.worker import get_worker_config
from eduid_common.rpc.celery import init_celery
from eduid_common.config.base import CommonConfig
from eduid_common.config.workers import MobConfig

import eduid_lookup_mobile.common as common

worker_config: MobConfig = MobConfig()

if common.celery is None:
    worker_config = get_worker_config('lookup_mobile', config_class=MobConfig)
    celery = init_celery('eduid_lookup_mobile', config=worker_config.celery, include=['eduid_lookup_mobile.tasks'])

    # When Celery starts the worker, it expects there to be a 'celery' in the module it loads,
    # but our tasks expect to find the Celery instance in common.celery - so copy it there
    common.celery = celery
