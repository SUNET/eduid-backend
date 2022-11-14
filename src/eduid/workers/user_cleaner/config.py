from enum import Enum
from typing import Dict

from pydantic import BaseModel

from eduid.common.config.base import LoggingConfigMixin, RootConfig
from eduid.userdb.meta import CleanerType


class WorkerInfo(BaseModel):
    user_count: int


class UserCleanerConfig(RootConfig, LoggingConfigMixin):
    mongo_uri: str = ""
    workers: Dict[str, WorkerInfo]
