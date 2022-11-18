import logging

from jwcrypto import jwk

from eduid.common.config.exceptions import BadConfiguration
from eduid.common.models.jose_models import RegisteredClaims
from eduid.workers.amapi.config import AMApiConfig

logger = logging.getLogger(__name__)


class AuthnBearerToken(RegisteredClaims):
    """
    Data we recognize from authentication bearer token JWT claims.
    """

    service_name: str


def load_jwks(config: AMApiConfig) -> jwk.JWKSet:
    if not config.keystore_path.exists():
        raise BadConfiguration(f"JWKS path {config.keystore_path} does not exist.")
    with config.keystore_path.open("r") as f:
        jwks = jwk.JWKSet.from_json(f.read())
        logger.info(f"jwks loaded from {config.keystore_path}")
    return jwks
