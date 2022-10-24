# -*- coding: utf-8 -*-
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import AnyUrl, BaseModel, Field, validator

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
    class Config:
        allow_population_by_field_name = True


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
    jwk: Optional[Union[ECJWK, RSAJWK, SymmetricJWK]]
    cert: Optional[str]
    cert_S256: Optional[str] = Field(default=None, alias="cert#S256")

    @validator("proof", pre=True)
    def expand_proof(cls, v: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
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
    actions: Optional[List[str]]
    # The location of the RS as an array of strings. These strings are
    # typically URIs identifying the location of the RS.
    locations: Optional[List[str]]
    # The kinds of data available to the client instance at the RS's API
    # as an array of strings.  For example, a client instance asking for
    # access to raw "image" data and "metadata" at a photograph API.
    datatypes: Optional[List[str]]
    # A string identifier indicating a specific resource at the RS. For
    # example, a patient identifier for a medical API or a bank account
    # number for a financial API.
    identifier: Optional[str]
    # The types or levels of privilege being requested at the resource.
    # For example, a client instance asking for administrative level
    # access, or access when the resource owner is no longer online.
    privileges: Optional[List[str]]
    # Sunet addition for requesting access to a specified scope
    scope: Optional[str]


class AccessTokenRequest(GnapBaseModel):
    access: Optional[List[Union[str, Access]]]
    # TODO: label is REQUIRED if used as part of a multiple access token request
    label: Optional[str]
    flags: Optional[List[AccessTokenFlags]]


class Client(GnapBaseModel):
    key: Union[str, Key]


class GrantRequest(GnapBaseModel):
    access_token: Union[AccessTokenRequest, List[AccessTokenRequest]]
    client: Union[str, Client]


class AccessTokenResponse(GnapBaseModel):
    value: str
    label: Optional[str]
    manage: Optional[AnyUrl]
    access: Optional[List[Union[str, Access]]]
    expires_in: Optional[int] = Field(default=None, description="seconds until expiry")
    key: Optional[Union[str, Key]]
    flags: Optional[List[AccessTokenFlags]]


class GrantResponse(GnapBaseModel):
    access_token: Optional[AccessTokenResponse]


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
    ath: Optional[str]
