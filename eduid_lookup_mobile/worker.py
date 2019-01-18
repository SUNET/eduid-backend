from __future__ import absolute_import

from eduid_common.rpc.worker import get_worker_config
from eduid_common.rpc.celery import init_celery

import eduid_lookup_mobile.common as common


worker_config = get_worker_config('lookup_mobile')
celery = init_celery('eduid_lookup_mobile', config=worker_config['CELERY'], include=['eduid_lookup_mobile.tasks'])

# When Celery starts the worker, it expects there to be a 'celery' in the module it loads,
# but our tasks expect to find the Celery instance in common.celery - so copy it there
common.celery = celery
