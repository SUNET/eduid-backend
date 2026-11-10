import logging
from datetime import datetime, timedelta, tzinfo
from typing import Any, NewType, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from eduid.common.config.base import AmConfigMixin, LoggingConfigMixin, MsgConfigMixin, RootConfig, StatsConfigMixin
from eduid.common.rpc.msg_relay import DeregisteredCauseCode
from eduid.userdb.identity import IdentityType

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
            if not data.keys() & need_one_of:
                raise ValueError(f"At least one of {need_one_of} must be set")
        return data


class SkvConfig(BaseModel):
    """
    Configuration for the SKV service.
    """

    termination_cause_codes: list[DeregisteredCauseCode] = Field(default_factory=list)


class IdentityAgeConfig(BaseModel):
    """
    Configuration for the gather_identity_age_users and process_identity_age_users jobs.

    gather_identity_age_users queues users with identities in the warning window or past the maximum age, and
    process_identity_age_users handles one queued user per run. The rate of warnings and unverifications is
    therefore set by the schedule of process_identity_age_users.

    Verified identities older than max_age_years are unverified. Users are warned by email
    warning_period_months before that happens, and are always given at least min_notice_days notice.

    Notification records are removed automatically when not modified for notification_auto_expire.

    With the job runner option dry_run the jobs make all decisions but send no mail and change no user. Dry runs use
    their own notification collection (identity_age_notifications_dry_run) so that the full flow of warning and
    later unverification can be simulated over several runs; real runs never see those records and dry runs never
    see the real ones. Drop the identity_age_notifications_dry_run collection to start a dry run over.
    """

    max_age_years: int = Field(default=5, ge=1)
    warning_period_months: int = Field(default=3, ge=0)
    min_notice_days: int = Field(default=30, ge=1)
    identity_types: list[IdentityType] = Field(default_factory=lambda: list(IdentityType))
    send_unverified_notice: bool = True
    mail_expires_in_days: int = Field(default=7, ge=1)
    notification_auto_expire: timedelta = Field(default=timedelta(days=3 * 365))

    @model_validator(mode="after")
    def warning_period_shorter_than_max_age(self) -> Self:
        if self.warning_period_months >= self.max_age_years * 12:
            raise ValueError(
                f"warning_period_months ({self.warning_period_months}) must be less than "
                f"max_age_years * 12 ({self.max_age_years * 12})"
            )
        return self

    @model_validator(mode="after")
    def auto_expire_longer_than_record_lifetime(self) -> Self:
        if self.notification_auto_expire <= timedelta(0):
            raise ValueError(f"notification_auto_expire ({self.notification_auto_expire}) must be positive")
        # A notification record must live from warning until unverification, at most this long
        min_lifetime = timedelta(days=self.warning_period_months * 31 + self.min_notice_days)
        if self.notification_auto_expire <= min_lifetime:
            raise ValueError(
                f"notification_auto_expire ({self.notification_auto_expire}) must be greater than "
                f"warning_period_months * 31 days + min_notice_days ({min_lifetime})"
            )
        return self


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
    skv: SkvConfig = Field(default_factory=SkvConfig)
    identity_age: IdentityAgeConfig = Field(default_factory=IdentityAgeConfig)
    dry_run: bool = False

    @field_validator("application_root")
    @classmethod
    def application_root_must_not_end_with_slash(cls, v: str) -> str:
        if v.endswith("/"):
            logger.warning(f"application_root should not end with slash ({v})")
            v = v.removesuffix("/")
        return v
