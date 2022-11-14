import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

from pydantic import Field, BaseModel, validator, root_validator

from eduid.common.config.base import LoggingConfigMixin, RootConfig

logger = logging.getLogger(__name__)


class Endpoint(BaseModel):
    commit_msg: str
    allowed: bool


class EndpointRestriction(BaseModel):
    endpoint: str
    method: str
    uri: Optional[str]

    @validator("endpoint", pre=True)
    def check_endpoint(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("endpoint must start with /")
        pos = 0
        for endpoint_part in v.split("/"):
            if pos == 0:
                if endpoint_part != "":
                    raise ValueError("endpoint not supported")
            elif pos == 1:
                if endpoint_part.isupper():
                    raise ValueError("endpoint parts need to be lower")
                if endpoint_part not in ["users"]:
                    raise ValueError("endpoint not supported")
            elif pos == 2:
                if not endpoint_part.isalpha() and endpoint_part not in ["*"]:
                    raise ValueError("blob in endpoint not supported")
            elif pos == 3:
                if endpoint_part not in ["mail", "phone", "language", "name"]:
                    raise ValueError("endpoint not supported")

            pos += 1
        return v

    @validator("method", pre=True)
    def check_method(cls, v: str) -> str:
        if v.isupper():
            raise ValueError("method have to be lower")
        if v not in ["put", "delete"]:
            raise ValueError(f"not supported method for endpoint {cls.endpoint}")
        return v

    @root_validator()
    def update_uri(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        method = values.get("method")
        endpoint = values.get("endpoint")
        values["uri"] = f"{method}:{endpoint}"
        return values

    @validator("uri", pre=True)
    def check_uri(cls, v: str):
        if v == "":
            raise ValueError("uri can't be empty")
        return v


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
    no_authn_urls: List[str] = Field(default=["get:/status/healthy", "get:/openapi.json"])
    status_cache_seconds: int = 10
    requested_access_type: Optional[str] = "am_api"
    user_restriction: Dict[str, List[EndpointRestriction]]
