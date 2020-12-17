from binascii import unhexlify
from typing import Optional

from pydantic.main import BaseModel


class VCCSConfig(BaseModel):
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
    yhsm_unlock_password: Optional[bytes] = None


def init_config():
    return VCCSConfig(
        add_creds_password_key_handle=1,
        yhsm_unlock_password=unhexlify('badabada'),
        mongo_uri='mongodb://mongodb.eduid.docker',
    )
