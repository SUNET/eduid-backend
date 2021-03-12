"""
The eduID messaging package.

Copyright (c) 2013, 2014, 2015, 2018 SUNET. All rights reserved.
See the file LICENSE.txt for full license statement.
"""
from typing import Optional

from eduid.common.config.base import CeleryConfig
from eduid.workers.msg.common import MsgCelerySingleton


def init_app(config: Optional[CeleryConfig]) -> None:
    MsgCelerySingleton.update_celery_config(config)
