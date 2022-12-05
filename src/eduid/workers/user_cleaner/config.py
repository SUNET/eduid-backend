from typing import Sequence

from pydantic import Field, BaseModel

from eduid.common.clients.gnap_client.base import GNAPClientAuthData
from eduid.common.config.base import LoggingConfigMixin, RootConfig, MsgConfigMixin, LoggingFilters, StatsConfigMixin


class AmAPIConfig(BaseModel):
    url: str
    tls_verify: bool


class UserCleanerConfig(RootConfig, LoggingConfigMixin, MsgConfigMixin, StatsConfigMixin):
    log_filters: Sequence[LoggingFilters] = Field(default=[LoggingFilters.NAMES])
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"
    mongo_uri: str = ""
    debug: bool
    user_count: int
    change_quota: float
    job_delay: float = 1.0
    gnap_auth_data: GNAPClientAuthData
    amapi: AmAPIConfig
