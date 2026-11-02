from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pygrindvakt import ConfigError, rp

__author__ = "lundberg"


# Asymmetric JWS algorithms accepted for ID token signatures (never "none" or the shared secret HS* family)
ASYMMETRIC_SIGNING_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
# pygrindvakt refuses a leeway above this many seconds
MAX_LEEWAY = rp.MAX_ID_TOKEN_LEEWAY


class OidcRpError(Exception):
    """The only OIDC RP client error type visible to webapps using OidcRpClient."""


class OidcRpClientConfig(BaseModel):
    # The issuer may embed credentials and client_secret is a secret: keep input values out of ValidationError text
    model_config = ConfigDict(hide_input_in_errors=True)

    client_id: str
    client_secret: str
    # The exact issuer string of the provider, used as is for discovery and issuer matching
    issuer: str
    code_challenge_method: str | None = Field(default="S256")
    acr_values: list[str] = Field(default_factory=list)
    # Reject ID tokens whose acr claim is missing or not in accepted_acr_values (default: acr_values). The OP is free to
    # authenticate at another level than the one requested, so this is what makes the requested level binding.
    require_acr: bool = False
    accepted_acr_values: list[str] | None = None
    # Reject ID tokens with a missing auth_time or an authentication older than this many seconds
    max_age: int | None = None
    scopes: list[str] = Field(default=["openid"])
    # ID token signature algorithms accepted from the provider
    allowed_algorithms: list[str] = Field(default=["RS256"])
    # Clock skew tolerance, in seconds, when validating ID token time claims
    leeway: int = 120
    # Reject ID tokens lacking at_hash / c_hash. When present they are always checked against the access token /
    # authorization code. Only enable for OPs known to send them in the code flow.
    require_at_hash: bool = False
    require_c_hash: bool = False
    userinfo_method: Literal["GET", "POST"] = "GET"
    # How a signed (application/jwt) userinfo response is proven to be a userinfo token. None means only
    # plain JSON userinfo responses are accepted. "typed" requires userinfo_typ (the JWT "typ" header value) and
    # is the only supported mode: the provider's key set also verifies ID tokens, so only a distinct "typ"
    # keeps an ID token from being accepted as a signed userinfo response.
    userinfo_trust: Literal["typed"] | None = None
    userinfo_typ: str | None = None

    @field_validator("leeway")
    @classmethod
    def _validate_leeway(cls, v: int) -> int:
        if not 0 <= v <= MAX_LEEWAY:
            raise ValueError(f"leeway must be between 0 and {MAX_LEEWAY} seconds")
        return v

    @field_validator("max_age")
    @classmethod
    def _validate_max_age(cls, v: int | None) -> int | None:
        if v is not None and v <= 0:
            raise ValueError("max_age must be positive")
        return v

    @field_validator("allowed_algorithms")
    @classmethod
    def _validate_allowed_algorithms(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("at least one allowed signing algorithm is required")
        unsupported = sorted(set(v) - ASYMMETRIC_SIGNING_ALGORITHMS)
        if unsupported:
            raise ValueError(f"unsupported signing algorithms: {unsupported}")
        return v

    @field_validator("issuer")
    @classmethod
    def _validate_issuer(cls, v: str) -> str:
        """
        Check the issuer syntax with pygrindvakt (https URL, plain http only for loopback hosts, no credentials,
        query, fragment, whitespace or backslashes) and require a host. The string is returned exactly as
        configured, it is used as is for discovery and issuer matching. Messages never echo the value,
        as it may contain credentials.
        """
        try:
            rp.validate_issuer(v)
            host = urlsplit(v).hostname
        except (ConfigError, ValueError):
            raise ValueError(
                "issuer must be an https URL (http only for loopback hosts) without credentials, query, "
                "fragment, whitespace or backslashes"
            ) from None
        if not host:  # pygrindvakt accepts e.g. "https:///oidc"
            raise ValueError("issuer must contain a host")
        return v

    @model_validator(mode="after")
    def _validate_acr(self) -> Self:
        if self.require_acr and not (self.accepted_acr_values or self.acr_values):
            raise ValueError("require_acr requires acr_values or accepted_acr_values")
        return self

    @model_validator(mode="after")
    def _validate_userinfo_trust(self) -> Self:
        if self.userinfo_trust == "typed" and not self.userinfo_typ:
            raise ValueError("userinfo_trust 'typed' requires userinfo_typ")
        if self.userinfo_typ is not None and self.userinfo_typ.lower() in {"jwt", "application/jwt"}:
            raise ValueError("userinfo_typ must be a type distinct from the generic JWT type")
        if self.userinfo_trust is None and self.userinfo_typ is not None:
            raise ValueError("userinfo_typ requires userinfo_trust")
        return self

    # How long (seconds) discovered provider metadata is cached
    discovery_ttl: int = Field(default=3600, ge=1)
    # Upper bound (seconds) for a discovery request, and for waiting for another thread's discovery
    discovery_timeout: int = Field(default=8, ge=1)
    # After a failed discovery, do not retry for this many seconds
    discovery_failure_backoff: int = Field(default=10, ge=0)
    # How long (seconds) an expired discovery document may still be served when refetching it fails
    discovery_max_stale: int = Field(default=3600, ge=0)
    # Outbound HTTP timeouts, in seconds
    http_connect_timeout: int = 5
    http_read_timeout: int = 15
    http_request_timeout: int = 30


@dataclass(frozen=True)
class AuthnRequestData:
    """An authorization request minted by the client. The RP must keep nonce/code_verifier until the callback."""

    url: str
    state: str
    nonce: str
    code_verifier: str | None
    redirect_uri: str


@dataclass(frozen=True)
class OidcAuthnResult:
    """The outcome of a successful code exchange: verified ID token claims and the raw token response."""

    claims: dict[str, Any]
    tokens: dict[str, Any]


class OidcRpClient(Protocol):
    """
    Interface for an OIDC Relying Party client, decoupling webapps from the underlying
    OIDC client implementation (currently pygrindvakt).

    The client keeps no per-login state: the caller stores state/nonce/code_verifier/redirect_uri
    (from AuthnRequestData) and hands them back to finish().
    """

    def mint_authn_request(self, redirect_uri: str, extra_params: Mapping[str, str] | None = None) -> AuthnRequestData:
        """Build an authorization request. extra_params may hold claims, acr_values, prompt etc."""
        ...

    def finish(self, code: str, *, redirect_uri: str, nonce: str, code_verifier: str | None) -> OidcAuthnResult:
        """Exchange the authorization code and verify the ID token."""
        ...

    def userinfo(self, result: OidcAuthnResult) -> dict[str, Any]:
        """Fetch userinfo using the access token in result, verifying sub against the ID token."""
        ...

    def end_session(self, id_token: str) -> None:
        """Best-effort call to the OIDC provider's end-session endpoint."""
        ...
