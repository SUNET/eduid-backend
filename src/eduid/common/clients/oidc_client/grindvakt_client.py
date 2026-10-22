from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from flask import Flask
from pygrindvakt import GrindvaktError, rp
from pygrindvakt import http as gv_http

from eduid.common.clients.oidc_client.base import AuthnRequestData, OidcAuthnResult, OidcRpClientConfig, OidcRpError

if TYPE_CHECKING:
    # stub-only protocol type, does not exist at runtime
    from pygrindvakt.http import HttpClientProtocol, HttpClientWithHeadersProtocol

__author__ = "lundberg"

logger = logging.getLogger(__name__)

# Anything raised by pygrindvakt (GrindvaktError and subclasses) or ValueError (raised for invalid
# arguments, e.g. a malformed redirect_uri) is turned into an OidcRpError so that webapps only
# have to handle a single error type from this module.
_CAUGHT_EXCEPTIONS = (GrindvaktError, ValueError)


def _wrap(operation: str, err: Exception) -> OidcRpError:
    """
    Build an OidcRpError from a pygrindvakt/ValueError exception.

    Only the exception class and the machine readable code are exposed: str(err) and the
    upstream_* attributes of GrindvaktError may echo secrets from the provider and must not be
    logged or shown to users.
    """
    code = getattr(err, "code", None)
    logger.warning(f"OIDC {operation} failed: {type(err).__name__} (code={code})")
    return OidcRpError(f"{operation} failed: {type(err).__name__} (code={code})")


@dataclass(frozen=True)
class _Provider:
    info: rp.ProviderInfo
    jwks: rp.JwksCache


class GrindvaktOidcRpClient:
    """OidcRpClient implementation backed by pygrindvakt. Keeps no per-login state."""

    def __init__(
        self,
        config: OidcRpClientConfig,
        http: HttpClientProtocol | gv_http.ReqwestClient | None = None,
        clock: Callable[[], float] = time.monotonic,
        discovery_http: HttpClientProtocol | gv_http.ReqwestClient | None = None,
    ) -> None:
        if config.code_challenge_method not in (None, "S256"):
            raise ValueError(f"Unsupported code_challenge_method: {config.code_challenge_method}")
        self._config = config
        self._issuer = config.issuer
        self._http = http if http is not None else gv_http.ReqwestClient()
        # discovery has its own, tighter, timeouts than token/userinfo requests
        self._discovery_http = discovery_http if discovery_http is not None else self._http
        self._clock = clock
        self._provider: _Provider | None = None
        self._provider_expires = 0.0
        self._failed_at: float | None = None
        self._lock = threading.Lock()

    def _get_provider(self) -> _Provider:
        # Discovery is done lazily so that an unreachable provider does not prevent app start. The result
        # is cached for discovery_ttl seconds. After a failure no new attempt is made for
        # discovery_failure_backoff seconds. Only one thread at a time does discovery:
        #  - with stale metadata, other threads keep serving it while one refreshes
        #  - on cold start, other threads wait at most discovery_timeout seconds for the one doing discovery
        now = self._clock()
        provider = self._provider
        if provider is not None and now < self._provider_expires:
            return provider
        if (backoff := self._backing_off(now)) is not None:
            return backoff
        if provider is not None:
            if not self._lock.acquire(blocking=False):
                return provider
        elif not self._lock.acquire(timeout=self._config.discovery_timeout):
            raise OidcRpError("discovery in progress, giving up waiting")
        try:
            return self._discover_locked()
        finally:
            self._lock.release()

    def _discover_locked(self) -> _Provider:
        # re-check, another thread may have finished while we waited for the lock
        now = self._clock()
        if self._provider is not None and now < self._provider_expires:
            return self._provider
        if (backoff := self._backing_off(now)) is not None:
            return backoff
        try:
            metadata = rp.discover(self._discovery_http, self._issuer)
            info = rp.ProviderInfo.from_metadata(metadata)
            if info.jwks_uri is None:
                raise ValueError("no jwks_uri in provider metadata")
            old = self._provider
            if old is not None and old.jwks.jwks_uri == info.jwks_uri and old.jwks.issuer == info.issuer:
                jwks = old.jwks  # keep the cached key set
            else:
                jwks = rp.JwksCache(self._http, info.jwks_uri, info.issuer)
        except _CAUGHT_EXCEPTIONS as err:
            self._failed_at = self._clock()
            # discovery errors (e.g. issuer mismatch) carry no secrets, unlike token endpoint errors
            logger.exception(f"OIDC discovery failed for issuer {self._issuer!r}")
            if self._provider is not None:
                # keep using the stale metadata until a refresh succeeds
                return self._provider
            raise _wrap("discovery", err) from None
        self._failed_at = None
        self._provider = _Provider(info=info, jwks=jwks)
        self._provider_expires = self._clock() + self._config.discovery_ttl
        return self._provider

    def _backing_off(self, now: float) -> _Provider | None:
        """Within the back-off after a failed discovery: return stale metadata if any, otherwise fail fast."""
        failed_at = self._failed_at
        if failed_at is None or now - failed_at >= self._config.discovery_failure_backoff:
            return None
        if self._provider is not None:
            return self._provider
        raise OidcRpError("discovery failed recently, not retrying yet")

    def _rp_client(self, redirect_uri: str) -> rp.RpClient:
        return rp.RpClient(
            self._config.client_id,
            redirect_uri,
            scope=" ".join(self._config.scopes),
            client_secret=self._config.client_secret,
        )

    def mint_authn_request(self, redirect_uri: str, extra_params: Mapping[str, str] | None = None) -> AuthnRequestData:
        provider = self._get_provider()
        extra = dict(extra_params or {})
        if self._config.acr_values and "acr_values" not in extra:
            extra["acr_values"] = " ".join(self._config.acr_values)
        try:
            url, state, nonce, verifier = rp.begin(
                provider.info,
                self._rp_client(redirect_uri),
                extra=extra,
                redirect_uri=redirect_uri,
                pkce=self._config.code_challenge_method == "S256",
            )
        except _CAUGHT_EXCEPTIONS as err:
            raise _wrap("authorization request", err) from None
        return AuthnRequestData(url=url, state=state, nonce=nonce, code_verifier=verifier, redirect_uri=redirect_uri)

    def finish(self, code: str, *, redirect_uri: str, nonce: str, code_verifier: str | None) -> OidcAuthnResult:
        provider = self._get_provider()
        try:
            token_set = rp.exchange_code(
                self._http,
                provider.info,
                self._rp_client(redirect_uri),
                code,
                code_verifier,
                redirect_uri=redirect_uri,
            )
            # at_hash/c_hash are checked when the OP sends them, and required per config
            claims = provider.jwks.verify_id_token(
                token_set.id_token,
                self._config.client_id,
                nonce,
                self._config.allowed_algorithms,
                leeway=self._config.leeway,
                access_token=token_set.access_token or None,
                authorization_code=code,
                require_at_hash=self._config.require_at_hash,
                require_c_hash=self._config.require_c_hash,
            )
        except _CAUGHT_EXCEPTIONS as err:
            raise _wrap("token exchange", err) from None
        return OidcAuthnResult(claims=claims, tokens=dict(token_set.raw))

    def userinfo(self, result: OidcAuthnResult) -> dict[str, Any]:
        provider = self._get_provider()
        sub = result.claims.get("sub")
        access_token = result.tokens.get("access_token")
        if not isinstance(sub, str) or not isinstance(access_token, str):
            raise OidcRpError("userinfo failed: missing sub or access_token")
        try:
            common: dict[str, Any] = {
                "jwks": provider.jwks,
                "client_id": self._config.client_id,
                "allowed_algorithms": self._config.allowed_algorithms,
            }
            if self._config.userinfo_trust is not None:
                # signed (application/jwt) userinfo responses are verified, see OidcRpClientConfig
                common["trust"] = self._config.userinfo_trust
                if self._config.userinfo_typ is not None:
                    common["typ"] = self._config.userinfo_typ
            endpoint = provider.info.userinfo_endpoint
            issuer = provider.info.issuer
            if self._config.userinfo_method == "GET":
                # our http client is required to support request headers on GET, otherwise pygrindvakt raises
                http = cast("HttpClientWithHeadersProtocol", self._http)
                userinfo: dict[str, Any] = rp.fetch_userinfo(
                    http, endpoint, access_token, sub, issuer, method="GET", **common
                )
            else:
                userinfo = rp.fetch_userinfo(self._http, endpoint, access_token, sub, issuer, method="POST", **common)
        except _CAUGHT_EXCEPTIONS as err:
            raise _wrap("userinfo", err) from None
        return userinfo

    def end_session(self, id_token: str) -> None:
        provider = self._get_provider()
        try:
            url = rp.end_session_url(provider.info, id_token_hint=id_token)
            self._http.get(url)
        except _CAUGHT_EXCEPTIONS as err:
            raise _wrap("end session", err) from None


def init_oidc_rp_client(
    app: Flask, name: str, config: OidcRpClientConfig, http: HttpClientProtocol | None = None
) -> GrindvaktOidcRpClient:
    """
    Set up a pygrindvakt-backed OIDC RP client.

    :param app: the Flask app the client is used by
    :param name: the name of the client, used in the User-Agent of outgoing requests
    :param config: the OIDC RP client configuration
    :param http: HTTP client to use for all requests to the provider (tests inject a static one)
    """
    app.logger.debug(f"Initializing OIDC RP client {name} for issuer {config.issuer}")
    if http is not None:
        return GrindvaktOidcRpClient(config, http=http)
    user_agent = f"eduid-{name}"
    return GrindvaktOidcRpClient(
        config,
        http=gv_http.ReqwestClient(
            connect_timeout=config.http_connect_timeout,
            read_timeout=config.http_read_timeout,
            request_timeout=config.http_request_timeout,
            user_agent=user_agent,
        ),
        discovery_http=gv_http.ReqwestClient(
            connect_timeout=min(5, config.discovery_timeout),
            read_timeout=min(3, config.discovery_timeout),
            request_timeout=config.discovery_timeout,
            user_agent=user_agent,
        ),
    )
