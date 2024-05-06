import logging

from pydantic import field_validator

from eduid.common.config.base import LoggingConfigMixin, RootConfig, StatsConfigMixin
from eduid.common.utils import removesuffix

logger = logging.getLogger(__name__)


class JobRunnerConfig(RootConfig, LoggingConfigMixin, StatsConfigMixin):
    """
    Configuration for the user-cleaner service.
    """

    application_root: str = ""
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"
    mongo_uri: str = ""
    status_cache_seconds: int = 10
    jobs: dict = {}

    @field_validator("application_root")
    @classmethod
    def application_root_must_not_end_with_slash(cls, v: str):
        if v.endswith("/"):
            logger.warning(f"application_root should not end with slash ({v})")
            v = removesuffix(v, "/")
        return v
