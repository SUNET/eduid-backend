import logging
from datetime import datetime, tzinfo
from typing import Any, NewType

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

    year: int | str | None = None
    month: int | str | None = None
    day: int | str | None = None
    week: int | str | None = None
    day_of_week: int | str | None = None
    hour: int | str | None = None
    minute: int | str | None = None
    second: int | str | None = None
    start_date: datetime | str | None = None
    end_date: datetime | str | None = None
    timezone: tzinfo | str | None = None
    jitter: int | None = None

    @model_validator(mode="before")
    @classmethod
    def at_least_one_datetime_value(cls, data: dict[str, Any]) -> dict[str, Any]:
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
    jobs: JobsConfig | None = None
    gnap_auth_data: GNAPClientAuthData

    @field_validator("application_root")
    @classmethod
    def application_root_must_not_end_with_slash(cls, v: str) -> str:
        if v.endswith("/"):
            logger.warning(f"application_root should not end with slash ({v})")
            v = removesuffix(v, "/")
        return v
