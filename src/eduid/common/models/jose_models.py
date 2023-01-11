import datetime
from enum import Enum
from typing import Optional, Union

from pydantic import AnyUrl, BaseModel, Field

__author__ = "lundberg"

from eduid.userdb.util import utc_now


class KeyType(str, Enum):
    EC = "EC"
    RSA = "RSA"
    OCT = "oct"


class KeyUse(str, Enum):
    SIGN = "sig"
    ENCRYPT = "enc"


class KeyOptions(str, Enum):
    SIGN = "sign"
    VERIFY = "verify"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    WRAP_KEY = "wrapKey"
    UNWRAP_KEY = "unwrapKey"
    DERIVE_KEY = "deriveKey"
    DERIVE_BITS = "deriveBits"


class SupportedAlgorithms(str, Enum):
    RS256 = "RS256"
    ES256 = "ES256"
    ES384 = "ES384"


class SupportedHTTPMethods(str, Enum):
    POST = "POST"


class JWK(BaseModel):
    kty: KeyType
    use: Optional[KeyUse]
    key_opts: Optional[list[KeyOptions]]
    alg: Optional[str]
    kid: Optional[str]
    x5u: Optional[str]
    x5c: Optional[str]
    x5t: Optional[str]
    x5tS256: Optional[str] = Field(alias="x5t#S256")


class ECJWK(JWK):
    crv: Optional[str]
    x: Optional[str]
    y: Optional[str]
    d: Optional[str]
    n: Optional[str]
    e: Optional[str]


class RSAJWK(JWK):
    d: Optional[str]
    n: Optional[str]
    e: Optional[str]
    p: Optional[str]
    q: Optional[str]
    dp: Optional[str]
    dq: Optional[str]
    qi: Optional[str]
    oth: Optional[str]
    r: Optional[str]
    t: Optional[str]


class SymmetricJWK(JWK):
    k: Optional[str]


class JWKS(BaseModel):
    keys: list[Union[ECJWK, RSAJWK, SymmetricJWK]]


class SupportedJWSType(str, Enum):
    JWS = "gnap-binding+jws"
    JWSD = "gnap-binding+jwsd"


class JOSEHeader(BaseModel):
    kid: Optional[str]
    alg: SupportedAlgorithms
    jku: Optional[AnyUrl]
    jwk: Optional[Union[ECJWK, RSAJWK, SymmetricJWK]]
    x5u: Optional[str]
    x5c: Optional[str]
    x5t: Optional[str]
    x5tS256: Optional[str] = Field(default=None, alias="x5t#S256")
    typ: Optional[str]
    cty: Optional[str]
    crit: Optional[list]


class RegisteredClaims(BaseModel):
    """
    https://tools.ietf.org/html/rfc7519#section-4.1
    """

    iss: Optional[str]  # Issuer
    sub: Optional[str]  # Subject
    aud: Optional[str]  # Audience
    exp: Optional[datetime.timedelta]  # Expiration Time
    nbf: datetime.datetime = Field(default_factory=utc_now)  # Not Before
    iat: datetime.datetime = Field(default_factory=utc_now)  # Issued At
    jti: Optional[str]  # JWT ID

    def to_rfc7519(self):
        d = self.dict(exclude_none=True)
        if self.exp:
            d["exp"] = int((self.iat + self.exp).timestamp())
        if self.nbf:
            d["nbf"] = int(self.nbf.timestamp())
        if self.iat:
            d["iat"] = int(self.iat.timestamp())
        return d
