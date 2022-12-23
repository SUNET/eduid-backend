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
    dry_run: bool = True
    debug: bool

    change_quota: float

    # amount of time to clean dataset, value in milliseconds
    time_to_clean_dataset: int = 2592000000

    # minimum time to delay each execution in milliseconds
    minimum_delay: int = 1000

    gnap_auth_data: GNAPClientAuthData
    amapi: AmAPIConfig
