from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import AnyUrl, BaseModel, Field

__author__ = "lundberg"


class OidcRpError(Exception):
    """The only OIDC RP client error type visible to webapps using OidcRpClient."""


class OidcStateCache(Protocol):
    """Duck-typed cache used by the OIDC RP client implementation to persist state/nonce data."""

    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str, expires: int | None = None) -> None: ...

    def delete(self, key: str) -> None: ...


class OidcRpClientConfig(BaseModel):
    client_id: str
    client_secret: str
    issuer: AnyUrl
    code_challenge_method: str | None = Field(default="S256")
    acr_values: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default=["openid"])


class OidcRpClient(Protocol):
    """
    Interface for an OIDC Relying Party client, decoupling webapps from the underlying
    OIDC client implementation (currently authlib).
    """

    def authorization_url(self, redirect_uri: str, extra_params: Mapping[str, str] | None = None) -> str:
        """Build the authorization request URL and persist state/nonce for later verification."""
        ...

    def fetch_token(self) -> dict[str, Any]:
        """Exchange the authorization code for a token. Must be called inside a Flask request context."""
        ...

    def userinfo(self) -> dict[str, Any]:
        """Fetch the userinfo from the OIDC provider's userinfo endpoint."""
        ...

    def server_metadata(self) -> Mapping[str, Any]:
        """Return the OIDC provider's server metadata (from the discovery document)."""
        ...

    def end_session(self, id_token: str) -> None:
        """Best-effort call to the OIDC provider's end-session endpoint."""
        ...
