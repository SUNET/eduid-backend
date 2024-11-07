import logging
from enum import StrEnum
from pathlib import Path
from typing import NewType

from pydantic import BaseModel, Field, field_validator

from eduid.common.config.base import LoggingConfigMixin, RootConfig

logger = logging.getLogger(__name__)


class SupportedMethod(StrEnum):
    DELETE = "delete"
    PUT = "put"
    GET = "get"


ServiceName = NewType("ServiceName", str)


class EndpointRestriction(BaseModel):
    endpoint: str = Field(min_length=1)
    method: SupportedMethod

    @field_validator("endpoint")
    @classmethod
    def check_endpoint(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("endpoint must start with /")
        return v.lower()

    @property
    def uri(self) -> str:
        return f"{self.method.value}:{self.endpoint}"


class AMApiConfig(RootConfig, LoggingConfigMixin):
    """
    Configuration for the User Management API app
    """

    protocol: str = "http"
    server_name: str = "localhost:8000"
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"
    mongo_uri: str = ""
    application_root: str = ""
    keystore_path: Path
    no_authn_urls: list[str] = Field(default=["/status/healthy", "/openapi.json"])
    status_cache_seconds: int = 10
    requested_access_type: str | None = "am_api"
    user_restriction: dict[ServiceName, list[EndpointRestriction]]
