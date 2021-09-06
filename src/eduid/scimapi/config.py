import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field, constr, validator

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
    data_owners: Dict[str, DataOwner] = Field(default={})
    # Map scope to data owner name
    scope_mapping: Dict[str, str] = Field(default={})
    # Allow someone with scope x to sudo to scope y
    scope_sudo: Dict[str, Set[str]] = Field(default={})
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

    @validator('scope_mapping')
    def validate_scope_mapping(cls, data: Dict[str, str]):
        """
        Scope mapping is a way to alias more than one scope to a single domain name,
        that can then map to a data owner. Turn all the keys and values into lowercase.
        """
        res = {}
        for k, v in data.items():
            if len(k) < len('x.se'):
                raise ValueError(f'Invalid domain name in scope_mapping LHS: {k}')
            if len(v) < len('x.se'):
                raise ValueError(f'Invalid domain name in scope_mapping RHS: {v}')
            res[k.lower()] = v.lower()
        return res

    @validator('scope_sudo')
    def validate_scope_sudo(cls, data: Dict[str, Set[str]]):
        """
        Scope mapping is a way to alias more than one scope to a single domain name,
        that can then map to a data owner. Turn all the keys and values into lowercase.
        """
        res = {}
        for k, v in data.items():
            if len(k) < len('x.se'):
                raise ValueError(f'Invalid domain name in scope_sudo LHS: {k}')
            new_v = set()
            for x in v:
                if len(x) < len('x.se'):
                    raise ValueError(f'Invalid domain name in scope_sudo RHS: {x}')
                new_v.add(x.lower())
            res[k.lower()] = new_v
        return res
