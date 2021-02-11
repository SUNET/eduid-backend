from typing import Dict, List

from pydantic import Field

from eduid_common.config.base import LoggingConfigMixin, RootConfig


class ScimApiConfig(RootConfig, LoggingConfigMixin):
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
    authorization_token_secret: str = 'secret'
    authorization_token_expire: int = 5 * 60
    no_authn_urls: List[str] = Field(default=['^/login$', '^/status/healthy$'])
    data_owners: List[str] = Field(default=['eduid.se'])
    # Invite config
    invite_url: str = ''
    invite_expire: int = 180 * 86400  # 180 days
