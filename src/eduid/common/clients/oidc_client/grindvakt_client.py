from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, NamedTuple, cast

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


# Floor for the discovery document lifetime (lower when discovery_ttl is), even if the OP sends no-cache or max-age=0
_MIN_DISCOVERY_TTL = 60
# How long (seconds) an expired discovery document may be served when refetching it fails
_MAX_DISCOVERY_STALE = 86400
# Error codes of pygrindvakt discovery failures that are expected and already logged by the original failure
_QUIET_DISCOVERY_CODES = ("discovery_backoff", "discovery_fetch_timeout")


class _Provider(NamedTuple):
    info: rp.ProviderInfo
    jwks: rp.JwksCache


class GrindvaktOidcRpClient:
    """OidcRpClient implementation backed by pygrindvakt. Keeps no per-login state."""

    def __init__(
        self,
        config: OidcRpClientConfig,
        redirect_uris: Sequence[str],
        http: HttpClientProtocol | gv_http.ReqwestClient | None = None,
        discovery_http: HttpClientProtocol | gv_http.ReqwestClient | None = None,
    ) -> None:
        if config.code_challenge_method not in (None, "S256"):
            raise ValueError(f"Unsupported code_challenge_method: {config.code_challenge_method}")
        if not redirect_uris:
            raise ValueError("at least one redirect_uri must be registered")
        self._config = config
        self._issuer = config.issuer
        # The redirect URIs are registered on the client, a per-request redirect_uri must match one of them exactly
        self._rp = rp.RpClient(
            config.client_id,
            redirect_uris[0],
            redirect_uris=list(redirect_uris),
            scope=" ".join(config.scopes),
            client_secret=config.client_secret,
        )
        self._http = http if http is not None else gv_http.ReqwestClient()
        # discovery has its own, tighter, timeouts than token/userinfo requests
        discovery_http = discovery_http if discovery_http is not None else self._http
        self._discovery = rp.DiscoveryCache(
            discovery_http,
            config.issuer,
            default_ttl=config.discovery_ttl,
            min_ttl=min(_MIN_DISCOVERY_TTL, config.discovery_ttl),
            max_ttl=config.discovery_ttl,
            failure_backoff=config.discovery_failure_backoff,
            stale_on_error=True,
            max_stale=_MAX_DISCOVERY_STALE,
            fetch_timeout=float(config.discovery_timeout),
        )
        self._compat_checked = False

    def _get_provider(self) -> _Provider:
        # Discovery is done lazily so that an unreachable provider does not prevent app start. The document is
        # cached by pygrindvakt for at most discovery_ttl seconds (less if the OP's Cache-Control says so). Only one
        # thread at a time fetches it, the others wait for that fetch for at most discovery_timeout seconds:
        #  - when that is not enough, they are given the stale document if there is one, otherwise they fail
        #  - after a failed fetch no new attempt is made for discovery_failure_backoff seconds, in that time
        #    (and when a refresh fails) the stale document is served for up to a day, otherwise calls fail fast
        try:
            info = self._discovery.info()
            jwks = self._discovery.jwks()
            if jwks.jwks_uri != info.jwks_uri:
                # the document was refreshed between the two calls and the jwks_uri changed, take info again
                info = self._discovery.info()
        except _CAUGHT_EXCEPTIONS as err:
            if getattr(err, "code", None) not in _QUIET_DISCOVERY_CODES:
                # discovery errors (e.g. issuer mismatch) carry no secrets, unlike token endpoint errors
                logger.exception(f"OIDC discovery failed for issuer {self._issuer!r}")
            raise _wrap("discovery", err) from None
        provider = _Provider(info=info, jwks=jwks)
        if not self._compat_checked:
            # advisory and never raises, concurrent first requests may at worst log the mismatches twice
            self._check_compatibility(info)
            self._compat_checked = True
        return provider

    def _check_compatibility(self, info: rp.ProviderInfo) -> None:
        """Log (advisory only) where the provider's discovery document contradicts our configuration."""
        try:
            mismatches = rp.check_rp_compatibility(
                info,
                client=self._rp,
                pkce=self._config.code_challenge_method == "S256",
                algorithms=self._config.allowed_algorithms,
                scopes=self._config.scopes,
                acr_values=self._config.acr_values or None,
            )
        except _CAUGHT_EXCEPTIONS:
            logger.exception(f"OIDC compatibility check failed for issuer {self._issuer!r}")
            return
        for mismatch in mismatches:
            logger.warning(f"OIDC provider {self._issuer!r} compatibility: {mismatch}")

    def mint_authn_request(self, redirect_uri: str, extra_params: Mapping[str, str] | None = None) -> AuthnRequestData:
        provider = self._get_provider()
        extra = dict(extra_params or {})
        if self._config.acr_values and "acr_values" not in extra:
            extra["acr_values"] = " ".join(self._config.acr_values)
        if self._config.max_age is not None and "max_age" not in extra:
            # lets the OP reauthenticate and return auth_time, which finish() checks against max_age
            extra["max_age"] = str(self._config.max_age)
        try:
            url, state, nonce, verifier = rp.begin(
                provider.info,
                self._rp,
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
                self._rp,
                code,
                code_verifier,
                redirect_uri=redirect_uri,
            )
            # at_hash/c_hash are checked when the OP sends them, and required per config
            accepted_acr = (
                (self._config.accepted_acr_values or self._config.acr_values) if self._config.require_acr else None
            )
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
                acr_values=accepted_acr,
                max_age=self._config.max_age,
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
    app: Flask,
    name: str,
    config: OidcRpClientConfig,
    redirect_uris: Sequence[str],
    http: HttpClientProtocol | None = None,
) -> GrindvaktOidcRpClient:
    """
    Set up a pygrindvakt-backed OIDC RP client.

    :param app: the Flask app the client is used by
    :param name: the name of the client, used in the User-Agent of outgoing requests
    :param config: the OIDC RP client configuration
    :param redirect_uris: the redirect URIs registered for the client, the first one is the primary
    :param http: HTTP client to use for all requests to the provider (tests inject a static one)
    """
    app.logger.debug(f"Initializing OIDC RP client {name} for issuer {config.issuer}")
    if http is not None:
        return GrindvaktOidcRpClient(config, redirect_uris, http=http)
    user_agent = f"eduid-{name}"
    return GrindvaktOidcRpClient(
        config,
        redirect_uris,
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
