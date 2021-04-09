import os
from typing import Any, Dict, Mapping, Optional

from binascii import unhexlify

from eduid_common.config.base import RootConfig
from eduid_common.config.parsers import load_config


class VCCSConfig(RootConfig):
    add_creds_password_key_handle: int
    mongo_uri: str
    # Optional arguments below
    add_creds_password_kdf_iterations: int = 50000
    add_creds_password_salt_bytes: int = 128 // 8
    debug: bool = False
    kdf_max_iterations: int = 500000
    kdf_min_iterations: int = 20000
    yhsm_debug: bool = False
    yhsm_device: str = '/dev/ttyACM0'
    yhsm_unlock_password: Optional[str] = None


def init_config(ns: str, app_name: str, test_config: Optional[Mapping[str, Any]] = None) -> VCCSConfig:
    config = load_config(typ=VCCSConfig, app_name=app_name, ns=ns, test_config=test_config)
    assert isinstance(config, VCCSConfig)  # convince mypy
    return config
