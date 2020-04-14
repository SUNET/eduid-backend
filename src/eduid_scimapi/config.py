from dataclasses import dataclass, field
from typing import Dict

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
