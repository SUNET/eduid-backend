from collections.abc import Mapping
from typing import Any

from fastapi import Request
from pydantic import BaseModel

from eduid.common.config.base import RootConfig
from eduid.common.config.parsers import load_config


class NewHasherNotConfigured(Exception):
    pass


class HasherConfig(BaseModel):
    add_creds_password_key_handle: int | None = None
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
    return load_config(typ=VCCSConfig, app_name=app_name, ns=ns, test_config=test_config)


def get_config(req: Request) -> VCCSConfig:
    """Pull the VCCS config off the FastAPI app state with a runtime type check."""
    config = req.app.state.config
    if not isinstance(config, VCCSConfig):
        raise RuntimeError(f"unexpected app.state.config type: {type(config).__name__}")
    return config
