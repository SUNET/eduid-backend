import sys

from eduid.common.config.workers import MsgConfig
from eduid.common.rpc.worker import get_worker_config
from eduid.workers.msg.common import MsgWorkerSingleton

# This is the Celery worker's entrypoint module - should not be imported anywhere!
if 'celery' not in sys.argv[0]:
    raise RuntimeError('Do not import the Celery worker entrypoint module')

app = MsgWorkerSingleton.celery

MsgWorkerSingleton.update_config(get_worker_config('msg', config_class=MsgConfig))
