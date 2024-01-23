import logging
from pathlib import Path

from pydantic import Field, validator

from eduid.common.config.base import LoggingConfigMixin, RootConfig
from eduid.common.utils import removesuffix

logger = logging.getLogger(__name__)


class MAccApiConfig(RootConfig, LoggingConfigMixin):
    """
    Configuration for the Managed Accounts API app
    """

    protocol: str = "http"
    server_name: str = "localhost:8000"
    application_root: str = ""
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"
    no_authn_urls: list[str] = Field(default=["^/status/healthy$", "^/docs/?$", "^/openapi.json"])
    vccs_url: str = "http://vccs:8080/"
    mongo_uri: str = ""
    authorization_mandatory: bool = True
    keystore_path: Path

    @validator("application_root")
    def application_root_must_not_end_with_slash(cls, v: str):
        if v.endswith("/"):
            logger.warning(f"application_root should not end with slash ({v})")
            v = removesuffix(v, "/")
        return v
