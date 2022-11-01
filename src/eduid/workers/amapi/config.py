import logging
from pathlib import Path
from typing import List, Optional, Mapping, Dict

from pydantic import Field, BaseModel

from eduid.common.config.base import LoggingConfigMixin, RootConfig

logger = logging.getLogger(__name__)


class Endpoint(BaseModel):
    commit_msg: str
    allowed: bool


class AMApiConfig(RootConfig, LoggingConfigMixin):
    """
    Configuration for the User Management API app
    """

    protocol: str = "http"
    server_name: str = "localhost:8000"
    application_root: str = ""
    log_format: str = "{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}"
    mongo_uri: str = ""
    keystore_path: Path
    no_authn_urls: List[str] = Field(default=["/status/healthy", "/openapi.json"])
    status_cache_seconds: int = 10
    requested_access_type: Optional[str] = "am_api"
    user_restriction: Dict[str, List[str]]
