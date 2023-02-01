from datetime import timedelta
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
    healthy_path: str = "/tmp/healthy"

    change_quota: float

    # amount of time to clean dataset, value in days
    periodicity: timedelta = timedelta(days=30)

    # minimum time to delay each execution in seconds
    minimum_delay: timedelta = timedelta(seconds=1)

    gnap_auth_data: GNAPClientAuthData
    amapi: AmAPIConfig
