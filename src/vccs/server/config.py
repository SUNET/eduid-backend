from binascii import unhexlify

from pydantic.main import BaseModel


class VCCSConfig(BaseModel):
    yhsm_unlock_password: bytes
    debug: bool = False
    yhsm_debug: bool = False

def init_config():
    return VCCSConfig(yhsm_unlock_password=unhexlify('badabada'))
