from binascii import unhexlify
from typing import Optional

from pydantic.main import BaseModel


class VCCSConfig(BaseModel):
    add_creds_password_key_handle: int
    yhsm_unlock_password: Optional[bytes] = None
    debug: bool = False
    yhsm_debug: bool = False
    yhsm_device: str = '/dev/ttyACM0'

def init_config():
    return VCCSConfig(add_creds_password_key_handle=1,
                      yhsm_unlock_password=unhexlify('badabada'),
                      )
