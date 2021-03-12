"""
The eduID Attribute Manager package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""

from eduid.common.config.base import CeleryConfig
from eduid.workers.am.common import AmCelerySingleton


def init_app(config: CeleryConfig) -> None:
    AmCelerySingleton.update_celery_config(config)
