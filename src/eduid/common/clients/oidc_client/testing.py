from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from eduid.common.clients.oidc_client.base import OidcRpError

__author__ = "lundberg"


@dataclass
class FakeOidcRpClient:
    """
    A fake OidcRpClient implementation for tests, avoiding the need to mock authlib internals.

    Configure the state/nonce and the token/userinfo payloads through the constructor, or by
    setting the attributes directly before calling the view under test. Use raise_on_* attributes
    to make a specific method raise OidcRpError, mimicking a failure from the real client.
    """

    authorization_endpoint: str = "https://example.com/op/authorize"
    state: str = "fake-state"
    nonce: str = "fake-nonce"
    token_response: dict[str, Any] = field(default_factory=dict)
    userinfo_response: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    raise_on_authorization_url: OidcRpError | None = None
    raise_on_fetch_token: OidcRpError | None = None
    raise_on_userinfo: OidcRpError | None = None
    raise_on_server_metadata: OidcRpError | None = None
    raise_on_end_session: OidcRpError | None = None

    end_session_calls: list[str] = field(default_factory=list)

    def authorization_url(self, redirect_uri: str, extra_params: Mapping[str, str] | None = None) -> str:
        if self.raise_on_authorization_url is not None:
            raise self.raise_on_authorization_url
        params = {
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "state": self.state,
            "nonce": self.nonce,
        }
        if extra_params:
            params.update(extra_params)
        return f"{self.authorization_endpoint}?{urlencode(params)}"

    def fetch_token(self) -> dict[str, Any]:
        if self.raise_on_fetch_token is not None:
            raise self.raise_on_fetch_token
        return self.token_response

    def userinfo(self) -> dict[str, Any]:
        if self.raise_on_userinfo is not None:
            raise self.raise_on_userinfo
        return self.userinfo_response

    def server_metadata(self) -> Mapping[str, Any]:
        if self.raise_on_server_metadata is not None:
            raise self.raise_on_server_metadata
        return self.metadata

    def end_session(self, id_token: str) -> None:
        if self.raise_on_end_session is not None:
            raise self.raise_on_end_session
        self.end_session_calls.append(id_token)
