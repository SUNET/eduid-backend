from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, field_validator

from eduid.common.models.jose_models import (
    ECJWK,
    RSAJWK,
    JOSEHeader,
    SupportedAlgorithms,
    SupportedHTTPMethods,
    SupportedJWSType,
    SymmetricJWK,
)

__author__ = "lundberg"


class GnapBaseModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)


class ProofMethod(str, Enum):
    DPOP = "dpop"
    HTTPSIGN = "httpsign"
    JWSD = "jwsd"
    JWS = "jws"
    MTLS = "mtls"
    OAUTHPOP = "oauthpop"
    TEST = "test"


class Proof(GnapBaseModel):
    method: ProofMethod


class Key(GnapBaseModel):
    proof: Proof
    jwk: ECJWK | RSAJWK | SymmetricJWK | None = None
    cert: str | None = None
    cert_S256: str | None = Field(default=None, alias="cert#S256")

    @field_validator("proof", mode="before")
    @classmethod
    def expand_proof(cls, v: str | dict[str, Any]) -> dict[str, Any]:
        # If additional parameters are not required or used for a specific method,
        # the method MAY be passed as a string instead of an object.
        if isinstance(v, str):
            return {"method": v}
        return v


class AccessTokenFlags(str, Enum):
    BEARER = "bearer"
    DURABLE = "durable"


class Access(GnapBaseModel):
    # The value of the "type" field is under the control of the AS.  This
    # field MUST be compared using an exact byte match of the string value
    # against known types by the AS.  The AS MUST ensure that there is no
    # collision between different authorization data types that it
    # supports.  The AS MUST NOT do any collation or normalization of data
    # types during comparison.  It is RECOMMENDED that designers of
    # general-purpose APIs use a URI for this field to avoid collisions
    # between multiple API types protected by a single AS.
    type: str
    # The types of actions the client instance will take at the RS as an
    # array of strings.  For example, a client instance asking for a
    # combination of "read" and "write" access.
    actions: list[str] | None = None
    # The location of the RS as an array of strings. These strings are
    # typically URIs identifying the location of the RS.
    locations: list[str] | None = None
    # The kinds of data available to the client instance at the RS's API
    # as an array of strings.  For example, a client instance asking for
    # access to raw "image" data and "metadata" at a photograph API.
    datatypes: list[str] | None = None
    # A string identifier indicating a specific resource at the RS. For
    # example, a patient identifier for a medical API or a bank account
    # number for a financial API.
    identifier: str | None = None
    # The types or levels of privilege being requested at the resource.
    # For example, a client instance asking for administrative level
    # access, or access when the resource owner is no longer online.
    privileges: list[str] | None = None
    # Sunet addition for requesting access to a specified scope
    scope: str | None = None


class AccessTokenRequest(GnapBaseModel):
    access: list[str | Access] | None = None
    # TODO: label is REQUIRED if used as part of a multiple access token request
    label: str | None = None
    flags: list[AccessTokenFlags] | None = None


class Client(GnapBaseModel):
    key: str | Key


class GrantRequest(GnapBaseModel):
    access_token: AccessTokenRequest | list[AccessTokenRequest]
    client: str | Client


class AccessTokenResponse(GnapBaseModel):
    value: str
    label: str | None = None
    manage: AnyUrl | None = None
    access: list[str | Access] | None = None
    expires_in: int | None = Field(default=None, description="seconds until expiry")
    key: str | Key | None = None
    flags: list[AccessTokenFlags] | None = None


class GrantResponse(GnapBaseModel):
    access_token: AccessTokenResponse | None = None


class GNAPJOSEHeader(JOSEHeader):
    kid: str
    alg: SupportedAlgorithms
    typ: SupportedJWSType
    htm: SupportedHTTPMethods
    # The HTTP URI used for this request, including all path and query components.
    uri: str
    # A timestamp of when the signature was created
    created: datetime
    # When a request is bound to an access token, the access token hash value. The value MUST be the result of
    # Base64url encoding (with no padding) the SHA-256 digest of the ASCII encoding of the associated access
    # token's value.  REQUIRED if the request protects an access token.
    ath: str | None = None
