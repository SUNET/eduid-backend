import sys

from eduid.common.config.workers import MobConfig
from eduid.common.rpc.worker import get_worker_config
from eduid.workers.lookup_mobile.common import MobWorkerSingleton

# This is the Celery worker's entrypoint module - should not be imported anywhere!
if 'celery' not in sys.argv[0]:
    raise RuntimeError('Do not import the Celery worker entrypoint module')

app = MobWorkerSingleton.celery

MobWorkerSingleton.update_config(get_worker_config('lookup_mobile', config_class=MobConfig))
