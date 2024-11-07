"""
eduID Lookup Mobile package.

Copyright (c) 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""

from eduid.common.config.base import CeleryConfig
from eduid.workers.lookup_mobile.common import MobCelerySingleton


def init_app(config: CeleryConfig) -> None:
    MobCelerySingleton.update_celery_config(config)
