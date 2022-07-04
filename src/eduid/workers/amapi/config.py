import logging
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Set

from pydantic import BaseModel, ConstrainedStr, Field, validator

from eduid.common.config.base import LoggingConfigMixin, RootConfig
from eduid.common.utils import removesuffix

logger = logging.getLogger(__name__)


class ReasonableDomainName(ConstrainedStr):
    min_length = len('x.se')
    to_lower = True


class ScopeName(ReasonableDomainName):
    pass


class DataOwnerName(ReasonableDomainName):
    pass


class AMApiConfig(RootConfig, LoggingConfigMixin):
    """
    Configuration for the User Management API app
    """

    protocol: str = 'http'
    server_name: str = 'localhost:8000'
    application_root: str = ''
    log_format: str = '{asctime} | {levelname:7} | {hostname} | {name:35} | {module:10} | {message}'
    mongo_uri: str = ''
    authorization_mandatory: bool = True
    authorization_token_expire: int = 5 * 60
    keystore_path: Path
    signing_key_id: str
    login_enabled: bool = False
    no_authn_urls: List[str] = Field(default=['^/login/?$', '^/status/healthy$', '^/docs/?$', '^/openapi.json'])
    status_cache_seconds: int = 10
    # The expected value of the authn JWT claims['requested_access']['type']
    allow_db_set: List[Mapping[str, str]]
    allow_db_unset: List[Mapping[str, str]]
    requested_access_type: Optional[str] = 'amapi'

    @validator('application_root')
    def application_root_must_not_end_with_slash(cls, v: str):
        if v.endswith('/'):
            logger.warning(f'application_root should not end with slash ({v})')
            v = removesuffix(v, '/')
        return v
