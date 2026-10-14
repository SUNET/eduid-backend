from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, Self

from pydantic import AnyUrl, BaseModel, Field, field_validator, model_validator

__author__ = "lundberg"


class OidcRpError(Exception):
    """The only OIDC RP client error type visible to webapps using OidcRpClient."""


class OidcRpClientConfig(BaseModel):
    client_id: str
    client_secret: str
    # The exact issuer string of the provider, used as is for discovery and issuer matching
    issuer: str
    code_challenge_method: str | None = Field(default="S256")
    acr_values: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default=["openid"])
    # ID token signature algorithms accepted from the provider
    allowed_algorithms: list[str] = Field(default=["RS256"])
    # Clock skew tolerance, in seconds, when validating ID token time claims
    leeway: int = 120
    userinfo_method: Literal["GET", "POST"] = "GET"
    # How a signed (application/jwt) userinfo response is proven to be a userinfo token. None means only
    # plain JSON userinfo responses are accepted. "typed" requires userinfo_typ (the JWT "typ" header value),
    # "dedicated_keys" is only safe if the provider's JWKS holds nothing but userinfo signing keys.
    userinfo_trust: Literal["typed", "dedicated_keys"] | None = None
    userinfo_typ: str | None = None

    @field_validator("issuer")
    @classmethod
    def _validate_issuer(cls, v: str) -> str:
        AnyUrl(v)  # syntax check only, the string is kept exactly as configured
        return v

    @model_validator(mode="after")
    def _validate_userinfo_trust(self) -> Self:
        if self.userinfo_trust == "typed" and not self.userinfo_typ:
            raise ValueError("userinfo_trust 'typed' requires userinfo_typ")
        if self.userinfo_trust is None and self.userinfo_typ is not None:
            raise ValueError("userinfo_typ requires userinfo_trust")
        return self

    # How long (seconds) discovered provider metadata is cached
    discovery_ttl: int = 3600
    # Upper bound (seconds) for a discovery request, and for waiting for another thread's discovery
    discovery_timeout: int = 8
    # After a failed discovery, do not retry for this many seconds
    discovery_failure_backoff: int = 10
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
