import logging

from jwcrypto import jwk
from uuid import uuid4
from pwgen import pwgen
import math
from eduid.common.config.exceptions import BadConfiguration
from eduid.maccapi.config import MAccApiConfig



logger = logging.getLogger(__name__)

def get_short_hash(entropy=8):
    return uuid4().hex[:entropy]

def generate_password(length: int = 12) -> str:
    password = pwgen(int(length), no_capitalize=True, no_symbols=True)
    password = " ".join([password[i * 4 : i * 4 + 4] for i in range(0, math.ceil(len(password) / 4))])

    return password

def load_jwks(config: MAccApiConfig) -> jwk.JWKSet:
    if not config.keystore_path.exists():
        raise BadConfiguration(f"JWKS path {config.keystore_path} does not exist")
    with open(config.keystore_path, "r") as f:
        jwks = jwk.JWKSet.from_json(f.read())
        logger.info(f"jwks loaded from {config.keystore_path}")
    return jwks
