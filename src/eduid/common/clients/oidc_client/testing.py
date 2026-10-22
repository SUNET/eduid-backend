import base64
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

from eduid.common.clients.oidc_client.base import AuthnRequestData, OidcAuthnResult, OidcRpError

__author__ = "lundberg"


@dataclass
class FakeOidcRpClient:
    """
    A fake OidcRpClient implementation for tests that do not need the real protocol handling.

    Configure the state/nonce and the claims/tokens/userinfo payloads through the constructor, or
    by setting the attributes directly before calling the view under test. Use raise_on_*
    attributes to make a specific method raise OidcRpError, mimicking a failure from the real
    client. No nonce or signature validation is done.
    """

    authorization_endpoint: str = "https://example.com/op/authorize"
    state: str = "fake-state"
    nonce: str = "fake-nonce"
    code_verifier: str | None = "fake-code-verifier"
    claims: dict[str, Any] = field(default_factory=dict)
    tokens: dict[str, Any] = field(default_factory=dict)
    userinfo_response: dict[str, Any] = field(default_factory=dict)

    raise_on_mint: OidcRpError | None = None
    raise_on_finish: OidcRpError | None = None
    raise_on_userinfo: OidcRpError | None = None
    raise_on_end_session: OidcRpError | None = None

    finish_calls: list[dict[str, Any]] = field(default_factory=list)
    end_session_calls: list[str] = field(default_factory=list)

    def mint_authn_request(self, redirect_uri: str, extra_params: Mapping[str, str] | None = None) -> AuthnRequestData:
        if self.raise_on_mint is not None:
            raise self.raise_on_mint
        params = {
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "state": self.state,
            "nonce": self.nonce,
        }
        if extra_params:
            params.update(extra_params)
        return AuthnRequestData(
            url=f"{self.authorization_endpoint}?{urlencode(params)}",
            state=self.state,
            nonce=self.nonce,
            code_verifier=self.code_verifier,
            redirect_uri=redirect_uri,
        )

    def finish(self, code: str, *, redirect_uri: str, nonce: str, code_verifier: str | None) -> OidcAuthnResult:
        self.finish_calls.append(
            {"code": code, "redirect_uri": redirect_uri, "nonce": nonce, "code_verifier": code_verifier}
        )
        if self.raise_on_finish is not None:
            raise self.raise_on_finish
        return OidcAuthnResult(claims=self.claims, tokens=self.tokens)

    def userinfo(self, result: OidcAuthnResult) -> dict[str, Any]:
        if self.raise_on_userinfo is not None:
            raise self.raise_on_userinfo
        return self.userinfo_response

    def end_session(self, id_token: str) -> None:
        if self.raise_on_end_session is not None:
            raise self.raise_on_end_session
        self.end_session_calls.append(id_token)


@dataclass
class RecordedRequest:
    method: str
    url: str
    form: list[tuple[str, str]] | None = None
    headers: list[tuple[str, str]] | None = None


def half_hash(value: str) -> str:
    """The OIDC at_hash/c_hash value (left half of the SHA-256 digest, base64url) for an access token or code.

    SHA-256 matches RS256/ES256 tokens only, the hash algorithm follows the JWT alg.
    """
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()


@dataclass
class StaticHttpClient:
    """
    A real (not mocked) pygrindvakt HTTP client implementation answering from a URL -> response map
    and recording every request made. Unknown URLs answer 404. Redirects are never followed.
    """

    responses: dict[str, tuple[int, bytes, str | None]] = field(default_factory=dict)
    requests: list[RecordedRequest] = field(default_factory=list)

    def add_json(self, url: str, payload: Mapping[str, Any], status: int = 200) -> None:
        self.responses[url] = (status, json.dumps(payload).encode(), "application/json")

    def requests_to(self, url: str) -> list[RecordedRequest]:
        return [req for req in self.requests if req.url.split("?")[0] == url]

    def _answer(self, url: str) -> tuple[int, bytes, str | None, list[tuple[str, str]]]:
        status, body, content_type = self.responses.get(url.split("?", maxsplit=1)[0], (404, b"", None))
        return status, body, content_type, [("cache-control", "max-age=3600")]

    def get(self, url: str) -> tuple[int, bytes, str | None, list[tuple[str, str]]]:
        self.requests.append(RecordedRequest(method="GET", url=url))
        return self._answer(url)

    def get_with_headers(
        self, url: str, headers: list[tuple[str, str]]
    ) -> tuple[int, bytes, str | None, list[tuple[str, str]]]:
        self.requests.append(RecordedRequest(method="GET", url=url, headers=headers))
        return self._answer(url)

    def post_form(
        self, url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]]
    ) -> tuple[int, bytes, str | None, list[tuple[str, str]]]:
        self.requests.append(RecordedRequest(method="POST", url=url, form=form, headers=headers))
        return self._answer(url)
