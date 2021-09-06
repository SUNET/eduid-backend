import logging
from pathlib import Path
from typing import Dict, List, NewType, Optional, Set

from pydantic import BaseModel, ConstrainedStr, Field, validator

from eduid.common.config.base import LoggingConfigMixin, RootConfig
from eduid.common.utils import removesuffix

logger = logging.getLogger(__name__)


class DataOwner(BaseModel):
    db_name: Optional[str] = None
    notify: List[str] = []


class AWSMixin(BaseModel):
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: Optional[str] = None


class ReasonableDomainName(ConstrainedStr):
    min_length = len('x.se')
    to_lower = True


class ScopeName(ReasonableDomainName):
    pass


class DataOwnerName(ReasonableDomainName):
    pass


class ScimApiConfig(RootConfig, LoggingConfigMixin, AWSMixin):
    """
    Configuration for the SCIM API app
    """

    protocol: str = 'http'
    server_name: str = 'localhost:8000'
    application_root: str = ''
    log_format: str = '{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}'
    mongo_uri: str = ''
    neo4j_uri: str = ''
    neo4j_config: Dict = Field(default_factory=dict)
    authorization_mandatory: bool = True
    authorization_token_expire: int = 5 * 60
    keystore_path: Path
    signing_key_id: str
    no_authn_urls: List[str] = Field(default=['^/login/?$', '^/status/healthy$', '^/docs/?$', '^/openapi.json'])
    status_cache_seconds: int = 10
    data_owners: Dict[DataOwnerName, DataOwner] = Field(default={})
    # Map scope to data owner name
    scope_mapping: Dict[ScopeName, DataOwnerName] = Field(default={})
    # Allow someone with scope x to sudo to scope y
    scope_sudo: Dict[ScopeName, Set[ScopeName]] = Field(default={})
    # The expected value of the authn JWT claims['requested_access']['type']
    requested_access_type: Optional[str] = 'scim-api'
    # Invite config
    invite_url: str = ''
    invite_expire: int = 180 * 86400  # 180 days

    @validator('application_root')
    def application_root_must_not_end_with_slash(cls, v: str):
        if v.endswith('/'):
            logger.warning(f'application_root should not end with slash ({v})')
            v = removesuffix(v, '/')
        return v
