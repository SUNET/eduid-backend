import logging
import math
from uuid import uuid4

from jwcrypto import jwk
from pwgen import pwgen

from eduid.common.config.exceptions import BadConfiguration
from eduid.maccapi.config import MAccApiConfig

logger = logging.getLogger(__name__)


def make_presentable_password(password: str) -> str:
    return " ".join([password[i * 4 : i * 4 + 4] for i in range(0, math.ceil(len(password) / 4))])


def load_jwks(config: MAccApiConfig) -> jwk.JWKSet:
    if not config.keystore_path.exists():
        raise BadConfiguration(f"JWKS path {config.keystore_path} does not exist")
    with open(config.keystore_path, "r") as f:
        jwks = jwk.JWKSet.from_json(f.read())
        logger.info(f"jwks loaded from {config.keystore_path}")
    return jwks
