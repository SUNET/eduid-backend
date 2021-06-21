from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from eduid.common.config.base import LoggingConfigMixin, RootConfig


class DataOwner(BaseModel):
    db_name: Optional[str] = None
    notify: List[str] = []


class AWSMixin(BaseModel):
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: Optional[str] = None


class ScimApiConfig(RootConfig, LoggingConfigMixin, AWSMixin):
    """
    Configuration for the SCIM API app
    """

    protocol: str = 'http'
    server_name: str = 'localhost:8000'
    application_root: str = '/'
    log_format: str = '{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}'
    mongo_uri: str = ''
    neo4j_uri: str = ''
    neo4j_config: Dict = Field(default_factory=dict)
    authorization_mandatory: bool = False
    authorization_token_expire: int = 5 * 60
    keystore_path: Path
    signing_key_id: str
    no_authn_urls: List[str] = Field(default=['^/login/$', '^/status/healthy/$'])
    status_cache_seconds: int = 10
    data_owners: Dict[str, DataOwner] = Field(default={})
    # Invite config
    invite_url: str = ''
    invite_expire: int = 180 * 86400  # 180 days
