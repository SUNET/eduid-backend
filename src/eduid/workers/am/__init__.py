"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
from typing import Optional

from celery import Celery

import eduid.workers.am.common as common
from eduid.common.config.base import CeleryConfig
from eduid.common.rpc.celery import init_celery


def init_app(config: Optional[CeleryConfig]) -> Celery:
    return init_celery('am', config)
