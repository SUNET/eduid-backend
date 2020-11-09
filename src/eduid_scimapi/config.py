from dataclasses import dataclass, field
from typing import Dict, List

from eduid_common.config.base import BaseConfig


@dataclass
class ScimApiConfig(BaseConfig):
    """
    Configuration for the SCIM API app
    """

    test: bool = False
    schema: str = 'http'
    server_name: str = 'localhost:8000'
    application_root: str = '/'
    neo4j_uri: str = ''
    neo4j_config: Dict = field(default_factory=dict)
    authorization_token_secret: str = 'secret'
    authorization_token_expire: int = 5 * 60
    no_authn_urls: List[str] = field(default_factory=lambda: ['^/login$', '^/status/healthy$'])
    data_owners: List[str] = field(default_factory=lambda: ['eduid.se'])
    # Invite config
    invite_url: str = ''
    invite_expire: int = 180 * 86400  # 180 days
