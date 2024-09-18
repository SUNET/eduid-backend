from collections.abc import Sequence

from eduid.common.config.base import EduidEnvironment, LoggingConfigMixin, LoggingFilters, RootConfig

__author__ = "lundberg"


class QueueWorkerConfig(RootConfig, LoggingConfigMixin):
    """
    Configuration for eduid-queue workers
    """

    environment: EduidEnvironment = EduidEnvironment.production
    mongo_uri: str = ""
    mongo_collection: str = ""
    periodic_interval: int = 10
    periodic_min_retry_wait_in_seconds: int = 10
    max_retries: int = 10
    audit: bool = True
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"
    log_filters: Sequence[LoggingFilters] = [LoggingFilters.NAMES]
    # Mail worker
    mail_host: str = "localhost"
    mail_port: int = 25
    mail_starttls: bool = False
    mail_verify_tls: bool = True
    mail_keyfile: str = ""
    mail_certfile: str = ""
    mail_username: str = ""
    mail_password: str = ""
    mail_default_from: str = "no-reply@eduid.se"
    mail_default_domain: str = "eduid.se"
