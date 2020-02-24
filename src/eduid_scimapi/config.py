import os
from dataclasses import asdict, dataclass
from typing import Dict

import yaml

from eduid_common.config.base import BaseConfig
from eduid_common.config.parsers.etcd import EtcdConfigParser


@dataclass
class ScimApiConfig(BaseConfig):
    """
    Configuration for the SCIM API app
    """
    test: bool = True


def load_config(config: Dict, name: str = 'scimapi', testing: bool=False) -> ScimApiConfig:
    try:
        # Init etcd config parsers
        common_parser = EtcdConfigParser('/eduid/api/common/')
        app_etcd_namespace = os.environ.get('EDUID_CONFIG_NS', '/eduid/api/{!s}/'.format(name))
        app_parser = EtcdConfigParser(app_etcd_namespace)
        # Load optional project wide settings
        common_config = common_parser.read_configuration(silent=False)
        if common_config:
            config.update(common_config)
        # Load optional app specific settings
        app_config = app_parser.read_configuration(silent=False)
        if app_config:
            config.update(app_config)
    except:
        if not testing:
            raise

    cfg = ScimApiConfig(**config)

    fd_int = os.open(f'/dev/shm/{name}_config.yaml', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd_int, 'w') as fd:
        fd.write('---\n')
        yaml.safe_dump(asdict(cfg), fd)

    return cfg
