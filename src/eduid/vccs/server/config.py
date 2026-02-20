from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

from eduid.common.config.base import RootConfig
from eduid.common.config.parsers import load_config


class HasherConfig(BaseModel):
    add_creds_password_key_handle: int
    add_creds_password_key_label: str | None = None


class YHSMConfig(HasherConfig):
    debug: bool = False
    device: str = "/dev/ttyACM0"
    unlock_password: str


class HSMKeyConfig(HasherConfig):
    module_path: str
    token_label: str
    user_pin: str | None = None
    so_pin: str | None = None


class SoftHasherConfig(HasherConfig):
    key_handles: dict[int, str]


class VCCSConfig(RootConfig):
    mongo_uri: str
    hasher: YHSMConfig | HSMKeyConfig | SoftHasherConfig
    new_hasher: HSMKeyConfig | SoftHasherConfig | None = None
    # Optional arguments below
    add_creds_password_kdf_iterations: int = 50000
    add_creds_password_salt_bytes: int = 128 // 8
    kdf_max_iterations: int = 500000
    kdf_min_iterations: int = 20000


def init_config(ns: str, app_name: str, test_config: Mapping[str, Any] | None = None) -> VCCSConfig:
    config = load_config(typ=VCCSConfig, app_name=app_name, ns=ns, test_config=test_config)
    assert isinstance(config, VCCSConfig)  # convince mypy
    return config
