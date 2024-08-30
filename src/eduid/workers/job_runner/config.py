import logging
from datetime import datetime, tzinfo
from typing import Any, NewType, Optional, Union

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from eduid.common.clients.gnap_client.base import GNAPClientAuthData
from eduid.common.config.base import AmConfigMixin, LoggingConfigMixin, MsgConfigMixin, RootConfig, StatsConfigMixin
from eduid.common.utils import removesuffix

logger = logging.getLogger(__name__)


class JobCronConfig(BaseModel):
    """
    Cron configuration for a single job.
    https://apscheduler.readthedocs.io/en/stable/modules/triggers/cron.html#module-apscheduler.triggers.cron
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    year: Optional[Union[int, str]] = None
    month: Optional[Union[int, str]] = None
    day: Optional[Union[int, str]] = None
    week: Optional[Union[int, str]] = None
    day_of_week: Optional[Union[int, str]] = None
    hour: Optional[Union[int, str]] = None
    minute: Optional[Union[int, str]] = None
    second: Optional[Union[int, str]] = None
    start_date: Optional[Union[datetime, str]] = None
    end_date: Optional[Union[datetime, str]] = None
    timezone: Optional[Union[tzinfo, str]] = None
    jitter: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def at_least_one_datetime_value(cls, data: Any) -> Any:
        if isinstance(data, dict):
            need_one_of = ["year", "month", "day", "week", "day_of_week", "hour", "minute", "second"]
            assert len(data.keys() & need_one_of), f"At least one of {need_one_of} must be set"
        return data


EnvironmentOrWorkerName = NewType("EnvironmentOrWorkerName", str)
JobName = NewType("JobName", str)
JobsConfig = NewType("JobsConfig", dict[EnvironmentOrWorkerName, dict[JobName, JobCronConfig]])


class JobRunnerConfig(RootConfig, LoggingConfigMixin, StatsConfigMixin, MsgConfigMixin, AmConfigMixin):
    """
    Configuration for the user-cleaner service.
    """

    application_root: str = ""
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"
    mongo_uri: str = ""
    status_cache_seconds: int = 10
    jobs: Optional[JobsConfig] = None
    gnap_auth_data: GNAPClientAuthData

    @field_validator("application_root")
    @classmethod
    def application_root_must_not_end_with_slash(cls, v: str):
        if v.endswith("/"):
            logger.warning(f"application_root should not end with slash ({v})")
            v = removesuffix(v, "/")
        return v
