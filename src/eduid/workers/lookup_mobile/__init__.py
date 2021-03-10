"""
eduID Lookup Mobile package.

Copyright (c) 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
import eduid.workers.lookup_mobile.common as common
from eduid.common.config.base import CeleryConfig
from eduid.common.rpc.celery import init_celery


def init_app(config: CeleryConfig):
    return init_celery('eduid_lookup_mobile', config)
