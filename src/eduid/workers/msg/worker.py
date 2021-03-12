import sys

from eduid.common.config.workers import MsgConfig
from eduid.common.rpc.worker import get_worker_config
from eduid.workers.msg.common import MsgCelerySingleton

# This is the Celery worker's entrypoint module - should not be imported anywhere!
if 'celery' not in sys.argv[0]:
    raise RuntimeError('Do not import the Celery worker entrypoint module')

app = MsgCelerySingleton.celery

MsgCelerySingleton.update_worker_config(get_worker_config('msg', config_class=MsgConfig))
