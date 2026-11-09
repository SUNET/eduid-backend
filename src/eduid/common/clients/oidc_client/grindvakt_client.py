from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from flask import Flask
from pygrindvakt import BadRequestError, ConfigError, GrindvaktError, keys, rp
from pygrindvakt import http as gv_http

from eduid.common.clients.oidc_client.base import (
    AuthnRequestData,
    CallbackParams,
    OidcAuthnResult,
    OidcCallback,
    OidcRpClientConfig,
    OidcRpError,
    OidcRpIssMismatchError,
)

if TYPE_CHECKING:
    # stub-only protocol type, does not exist at runtime
    from pygrindvakt.http import HttpClientProtocol, HttpClientWithHeadersProtocol

__author__ = "lundberg"

logger = logging.getLogger(__name__)

# Anything raised by pygrindvakt (GrindvaktError and subclasses) or ValueError (raised for invalid
# arguments, e.g. a malformed redirect_uri) is turned into an OidcRpError so that webapps only
# have to handle a single error type from this module.
# A PEM private key is a few KiB, anything bigger is not a key file
_MAX_KEY_FILE_SIZE = 64 * 1024
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


def parse_authorization_callback(
    params: CallbackParams | Sequence[tuple[str, str]], *, issuer: str, require_iss: bool
) -> OidcCallback:
    """
    Shape-check an authorization response and compare its iss (RFC 9207) with issuer. Makes no provider requests.

    A present iss is always compared, require_iss only decides if a missing iss is an error. This also applies to
    error responses. Raises OidcRpError for malformed/ambiguous responses and OidcRpIssMismatchError for iss mismatches.

    A rejection is logged here, and only here: INFO for a malformed response, WARNING for an iss mismatch. Callers
    count it but must not log it again.
    """
    try:
        resp = rp.parse_authorization_response(params)
    except BadRequestError as err:
        # the message of BadRequestError is fixed text and never echoes request values
        logger.info(f"OIDC authorization response rejected: {err}")
        raise OidcRpError(f"authorization response rejected: {err}") from None
    except GrindvaktError as err:
        raise _wrap("authorization response", err) from None
    if not resp.matches_iss(issuer, required=require_iss):
        logger.warning(
            f"OIDC authorization response iss mismatch: iss is None: {resp.iss is None}, "
            f"iss: {(resp.iss or '')[:256]!r}"
        )
        raise OidcRpIssMismatchError("authorization response iss mismatch")
    return OidcCallback(
        state=resp.state,
        code=resp.code,
        error=resp.error,
        error_known=resp.error_known,
        error_description_safe=resp.error_description_safe,
    )


# pygrindvakt's DiscoveryCache builds its JwksCache from the one http client it is given, so JWKS fetches use the
# discovery client (and its tight discovery_timeout budget), not the token/userinfo client. This was accepted: an
# expired key set is never served, so a JWKS fetch slower than discovery_timeout fails the login until the next try.
# Raise discovery_timeout for an OP with a slow or large jwks_uri. The JwksCache TTLs are pygrindvakt's defaults.
# Floor for the discovery document lifetime (lower when discovery_ttl is), even if the OP sends no-cache or max-age=0
_MIN_DISCOVERY_TTL = 60
# How many times info and jwks are read again when a refresh by another thread changes the jwks_uri between the reads
_PROVIDER_READ_ATTEMPTS = 3
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
        # Loaded here so that a bad key is a config error at app start, not at the first request
        self._signing_key = self._load_pem_key(
            config.client_signing_key_path,
            config.client_signing_alg,
            config.client_signing_key_kid,
            "client_signing_key",
        )
        # Request objects are visible in the authorization URL: a separate key if configured, else the client key
        self._request_object_key = (
            self._load_pem_key(
                config.client_request_object_key_path,
                config.client_request_object_signing_alg,
                config.client_request_object_key_kid,
                "client_request_object_key",
            )
            or self._signing_key
        )
        # The redirect URIs are registered on the client, a per-request redirect_uri must match one of them exactly
        try:
            self._rp = rp.RpClient(
                config.client_id,
                redirect_uris[0],
                redirect_uris=list(redirect_uris),
                scope=" ".join(config.scopes),
                client_secret=config.client_secret,
                auth_method=config.token_endpoint_auth_method,
                signing_key=self._signing_key if config.token_endpoint_auth_method == "private_key_jwt" else None,
            )
        except _CAUGHT_EXCEPTIONS as err:
            # pygrindvakt config errors name parameters, never values, so the message is safe to include
            detail = f": {err}" if isinstance(err, ConfigError) else ""
            raise ValueError(f"invalid OIDC client configuration: {type(err).__name__}{detail}") from None
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
            max_stale=config.discovery_max_stale,
            fetch_timeout=float(config.discovery_timeout),
        )
        self._compat_checked = False
        # The key cache last handed out. DiscoveryCache keeps one JwksCache object while the jwks_uri and issuer are
        # unchanged, so it is reused to avoid a second wait on an in-flight refresh (see _get_provider).
        self._jwks: rp.JwksCache | None = None

    @staticmethod
    def _load_pem_key(path: Path | str | None, alg: str | None, kid: str | None, name: str) -> keys.SigningKey | None:
        """Load a PEM signing key, if configured. Error text never includes key material."""
        if not path:
            return None
        key_path = Path(path)
        try:
            # is_file() is False for directories, FIFOs and devices, so reading cannot block on them
            if not key_path.is_file():
                raise ValueError(f"{name}_path {str(key_path)!r} is not a regular file")
            if key_path.stat().st_size > _MAX_KEY_FILE_SIZE:
                raise ValueError(f"{name}_path {str(key_path)!r} is larger than {_MAX_KEY_FILE_SIZE} bytes")
            data = key_path.read_bytes()
        except OSError as err:
            raise ValueError(f"cannot read {name}_path {str(key_path)!r}: {type(err).__name__}") from None
        try:
            key = keys.signing_key_from_pem(data, alg, kid)
            thumbprint = keys.jwk_thumbprint(key.public_jwk())
        except _CAUGHT_EXCEPTIONS as err:
            raise ValueError(f"invalid {name} in {str(key_path)!r}: {type(err).__name__}") from None
        # public information only
        logger.info(
            f"Loaded {name} {str(key_path.resolve())!r}: kid={key.kid}, alg={key.alg}, jwk thumbprint={thumbprint}"
        )
        return key

    def _get_provider(self) -> _Provider:
        # Discovery is done lazily so that an unreachable provider does not prevent app start. The document is
        # cached by pygrindvakt for at most discovery_ttl seconds (less if the OP's Cache-Control says so). Only one
        # thread at a time fetches it, the others wait for that fetch for at most discovery_timeout seconds:
        #  - when that is not enough, they are given the stale document if there is one, otherwise they fail
        #  - after a failed fetch no new attempt is made for discovery_failure_backoff seconds, in that time
        #    (and when a refresh fails) the stale document is served for up to discovery_max_stale seconds,
        #    otherwise calls fail fast
        # The issuer of the document is checked on every fetch, and the JwksCache is replaced when the jwks_uri or
        # issuer changes: both are delegated to pygrindvakt and pinned by tests, a pygrindvakt bump must keep them.
        try:
            for _ in range(_PROVIDER_READ_ATTEMPTS):
                info = self._discovery.info()
                known = self._jwks
                if known is not None and known.jwks_uri == info.jwks_uri and known.issuer == info.issuer:
                    # no second cache lookup: while a refresh is in flight each lookup waits up to discovery_timeout
                    jwks = known
                else:
                    jwks = self._discovery.jwks()
                if jwks.jwks_uri == info.jwks_uri:
                    break
                # the document was refreshed between the two reads and the jwks_uri changed, read both again
            else:
                raise OidcRpError("discovery metadata changed while it was being read")
        except OidcRpError:
            logger.warning(f"OIDC discovery for issuer {self._issuer!r}: jwks_uri keeps changing between reads")
            raise
        except _CAUGHT_EXCEPTIONS as err:
            if getattr(err, "code", None) not in _QUIET_DISCOVERY_CODES:
                # discovery errors (e.g. issuer mismatch) carry no secrets, unlike token endpoint errors
                logger.exception(f"OIDC discovery failed for issuer {self._issuer!r}")
            raise _wrap("discovery", err) from None
        self._jwks = jwks
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
        # advisory: RFC 9207 iss support as advertised by the OP (raw metadata, not otherwise exposed)
        raw = getattr(getattr(info, "metadata", None), "raw", None)
        advertised = raw.get("authorization_response_iss_parameter_supported") if isinstance(raw, Mapping) else None
        if advertised is True and not self._config.require_iss:
            logger.warning(
                f"OIDC provider {self._issuer!r} advertises authorization_response_iss_parameter_supported, "
                "consider require_iss=True"
            )
        elif advertised is not True and self._config.require_iss:
            logger.warning(
                f"OIDC provider {self._issuer!r} does not advertise authorization_response_iss_parameter_supported "
                "but require_iss is True, callbacks without iss will be rejected"
            )

    def parse_callback(self, params: CallbackParams | Sequence[tuple[str, str]]) -> OidcCallback:
        # No _get_provider(): this needs no discovery, so a bad callback never triggers provider requests
        return parse_authorization_callback(params, issuer=self._issuer, require_iss=self._config.require_iss)

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
                request_object_key=self._request_object_key if self._config.use_request_object else None,
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
