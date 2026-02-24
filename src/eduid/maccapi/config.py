import logging

from pydantic import field_validator

from eduid.common.config.base import AuthnBearerTokenConfig, LoggingConfigMixin, StatsConfigMixin, VCCSConfigMixin

logger = logging.getLogger(__name__)


class MAccApiConfig(AuthnBearerTokenConfig, LoggingConfigMixin, StatsConfigMixin, VCCSConfigMixin):
    """
    Configuration for the Managed Accounts API app
    """

    vccs_url: str = "http://vccs:8080/"
    # The expected value of the authn JWT claims['requested_access']['type']
    requested_access_type: str | None = "maccapi"

    status_cache_seconds: int = 10

    log_retention_days: int = 730
    account_retention_days: int = 365

    @field_validator("application_root")
    @classmethod
    def application_root_must_not_end_with_slash(cls, v: str) -> str:
        if v.endswith("/"):
            logger.warning(f"application_root should not end with slash ({v})")
            v = v.removesuffix("/")
        return v
