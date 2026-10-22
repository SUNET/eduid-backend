import dataclasses
import logging
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from flask import Flask
from pydantic import ValidationError
from pygrindvakt import http as gv_http
from pygrindvakt import jwt, keys, rp
from pygrindvakt.keys import SigningKey
from pygrindvakt.metadata import ProviderMetadata
from pytest_mock import MockerFixture

from eduid.common.clients.oidc_client.base import OidcAuthnResult, OidcRpClientConfig, OidcRpError
from eduid.common.clients.oidc_client.grindvakt_client import GrindvaktOidcRpClient, init_oidc_rp_client
from eduid.common.clients.oidc_client.testing import RecordedRequest, StaticHttpClient, half_hash

__author__ = "lundberg"

ISSUER = "https://op.example.com/op"
CLIENT_ID = "test_client"
REDIRECT_URI = "https://rp.example.com/callback"
CODE_VERIFIER = "v" * 43


def _signing_key(kid: str = "key1", alg: str = "RS256") -> SigningKey:
    jwk = keys.generate_ec_jwk() if alg == "ES256" else keys.generate_rsa_jwk()
    return keys.signing_key_from_jwk(jwk, alg, kid)


class TestGrindvaktOidcRpClient:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.key = _signing_key()
        metadata = ProviderMetadata(ISSUER, ISSUER)
        metadata.end_session_endpoint = f"{ISSUER}/logout"
        self.metadata = metadata.to_dict()
        self.http = StaticHttpClient()
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", self.metadata)
        self.http.add_json(self.metadata["jwks_uri"], self.key.to_public_jwks())
        self.http.add_json(self.metadata["userinfo_endpoint"], {"sub": "subject", "name": "Test"})

    def _client(self, **config: Any) -> GrindvaktOidcRpClient:
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, **config)
        return GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=self.http)

    def _id_token(self, nonce: str, key: SigningKey | None = None, **claims: Any) -> str:
        now = int(time.time())
        payload: dict[str, Any] = {
            "iss": ISSUER,
            "sub": "subject",
            "aud": CLIENT_ID,
            "exp": now + 300,
            "iat": now,
            "nonce": nonce,
        }
        payload.update(claims)
        return jwt.sign(key or self.key, payload)

    def _token_response(self, id_token: str) -> None:
        self.http.add_json(
            self.metadata["token_endpoint"],
            {"access_token": "access_token", "token_type": "Bearer", "id_token": id_token, "expires_in": 3600},
        )

    def _finish(self, client: GrindvaktOidcRpClient, id_token: str, nonce: str) -> OidcAuthnResult:
        self._token_response(id_token)
        return client.finish("code", redirect_uri=REDIRECT_URI, nonce=nonce, code_verifier=CODE_VERIFIER)

    def test_mint_with_pkce(self) -> None:
        data = self._client().mint_authn_request(REDIRECT_URI)

        query = parse_qs(urlparse(data.url).query)
        assert data.url.startswith(self.metadata["authorization_endpoint"])
        assert query["state"] == [data.state]
        assert query["nonce"] == [data.nonce]
        assert query["client_id"] == [CLIENT_ID]
        assert query["redirect_uri"] == [REDIRECT_URI]
        assert query["code_challenge_method"] == ["S256"]
        assert "code_challenge" in query
        assert data.code_verifier
        assert data.redirect_uri == REDIRECT_URI

    def test_mint_without_pkce(self) -> None:
        data = self._client(code_challenge_method=None).mint_authn_request(REDIRECT_URI)

        query = parse_qs(urlparse(data.url).query)
        assert data.code_verifier is None
        assert "code_challenge" not in query
        assert query["state"] == [data.state]
        assert query["nonce"] == [data.nonce]
        assert data.state != data.nonce

    def test_acr_values_and_extra_params_reach_url(self) -> None:
        client = self._client(acr_values=["loa3", "loa2"], scopes=["openid", "profile"])

        data = client.mint_authn_request(REDIRECT_URI, extra_params={"claims": '{"userinfo": {"id": null}}'})

        query = parse_qs(urlparse(data.url).query)
        assert query["acr_values"] == ["loa3 loa2"]
        assert query["claims"] == ['{"userinfo": {"id": null}}']
        assert query["scope"] == ["openid profile"]

    def test_unregistered_redirect_uri_rejected_on_mint(self) -> None:
        client = self._client()

        with pytest.raises(OidcRpError):
            client.mint_authn_request("https://evil.example.com/callback")

    def test_unregistered_redirect_uri_rejected_on_finish(self) -> None:
        client = self._client()
        id_token = self._id_token("nonce")
        self._token_response(id_token)

        with pytest.raises(OidcRpError):
            client.finish("code", redirect_uri="https://evil.example.com/callback", nonce="nonce", code_verifier=None)

    def test_secondary_registered_redirect_uri_accepted(self) -> None:
        other = "https://rp.example.com/other"
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER)
        client = GrindvaktOidcRpClient(conf, [REDIRECT_URI, other], http=self.http)

        request = client.mint_authn_request(other)

        assert request.redirect_uri == other

    def test_no_redirect_uris_rejected(self) -> None:
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER)

        with pytest.raises(ValueError, match="redirect_uri"):
            GrindvaktOidcRpClient(conf, [], http=self.http)

    def test_discovery_is_done_once(self) -> None:
        client = self._client()

        client.mint_authn_request(REDIRECT_URI)
        client.mint_authn_request(REDIRECT_URI)
        assert client._get_provider().info.issuer == ISSUER

        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 1

    def test_discovery_failure_backoff_fails_fast(self) -> None:
        now = [1000.0]
        client = self._client(discovery_failure_backoff=10)
        client._clock = lambda: now[0]
        del self.http.responses[f"{ISSUER}/.well-known/openid-configuration"]

        for _ in range(2):
            with pytest.raises(OidcRpError):
                client.mint_authn_request(REDIRECT_URI)
        # the second call failed without any request to the OP
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 1

        # after the back-off a new attempt is made, and succeeds
        now[0] += 11
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", self.metadata)
        assert client.mint_authn_request(REDIRECT_URI).state
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 2

    def test_discovery_refreshed_after_ttl(self) -> None:
        now = [1000.0]
        client = self._client(discovery_ttl=3600)
        client._clock = lambda: now[0]

        client.mint_authn_request(REDIRECT_URI)
        now[0] += 3599
        client.mint_authn_request(REDIRECT_URI)
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 1

        changed = {**self.metadata, "token_endpoint": f"{ISSUER}/new-token"}
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", changed)
        now[0] += 2
        assert client._get_provider().info.token_endpoint == f"{ISSUER}/new-token"
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 2

    def test_jwks_cache_reused_when_jwks_uri_and_issuer_unchanged(self) -> None:
        now = [1000.0]
        client = self._client(discovery_ttl=100)
        client._clock = lambda: now[0]
        first = client._get_provider().jwks

        now[0] += 101

        assert client._get_provider().jwks is first

    def test_jwks_cache_not_reused_when_issuer_differs(self) -> None:
        now = [1000.0]
        client = self._client(discovery_ttl=100)
        client._clock = lambda: now[0]
        provider = client._get_provider()
        # a cache bound to another issuer, with the same jwks_uri as the refreshed metadata
        stale = rp.JwksCache(self.http, self.metadata["jwks_uri"], "https://other.example.com")
        client._provider = dataclasses.replace(provider, jwks=stale)

        now[0] += 101
        refreshed = client._get_provider().jwks

        assert refreshed is not stale
        assert refreshed.issuer == ISSUER

    def test_stale_metadata_used_when_refresh_fails(self) -> None:
        now = [1000.0]
        client = self._client(discovery_ttl=100, discovery_failure_backoff=10)
        client._clock = lambda: now[0]
        client.mint_authn_request(REDIRECT_URI)
        del self.http.responses[f"{ISSUER}/.well-known/openid-configuration"]

        now[0] += 101
        assert client.mint_authn_request(REDIRECT_URI).state  # stale metadata, refresh failed
        assert client.mint_authn_request(REDIRECT_URI).state  # backing off, no new request
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 2

    def test_finish_success_sends_code_verifier(self) -> None:
        client = self._client()
        data = client.mint_authn_request(REDIRECT_URI)

        result = self._finish(client, self._id_token(data.nonce), data.nonce)

        assert result.claims["sub"] == "subject"
        assert result.tokens["access_token"] == "access_token"
        assert "id_token" in result.tokens
        (token_request,) = self.http.requests_to(self.metadata["token_endpoint"])
        assert token_request.form is not None
        form = dict(token_request.form)
        assert form["code"] == "code"
        assert form["code_verifier"] == CODE_VERIFIER
        assert form["redirect_uri"] == REDIRECT_URI

    def test_at_hash_matching_accepted(self) -> None:
        client = self._client()

        result = self._finish(client, self._id_token("nonce", at_hash=half_hash("access_token")), "nonce")

        assert result.claims["at_hash"] == half_hash("access_token")

    def test_at_hash_mismatch_rejected(self) -> None:
        client = self._client()
        id_token = self._id_token("nonce", at_hash=half_hash("another_access_token"))

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_missing_at_hash_accepted(self) -> None:
        result = self._finish(self._client(), self._id_token("nonce"), "nonce")

        assert "at_hash" not in result.claims

    def test_require_at_hash_missing_rejected(self) -> None:
        client = self._client(require_at_hash=True)
        id_token = self._id_token("nonce")

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_require_at_hash_mismatch_rejected(self) -> None:
        client = self._client(require_at_hash=True)
        id_token = self._id_token("nonce", at_hash=half_hash("another_access_token"))

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_require_at_hash_matching_accepted(self) -> None:
        client = self._client(require_at_hash=True)

        result = self._finish(client, self._id_token("nonce", at_hash=half_hash("access_token")), "nonce")

        assert result.claims["sub"] == "subject"

    def test_c_hash_mismatch_rejected(self) -> None:
        client = self._client()
        id_token = self._id_token("nonce", c_hash=half_hash("another_code"))

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_c_hash_matching_accepted(self) -> None:
        result = self._finish(self._client(), self._id_token("nonce", c_hash=half_hash("code")), "nonce")

        assert result.claims["c_hash"] == half_hash("code")

    def test_missing_c_hash_accepted(self) -> None:
        result = self._finish(self._client(), self._id_token("nonce"), "nonce")

        assert "c_hash" not in result.claims

    def test_require_c_hash_missing_rejected(self) -> None:
        client = self._client(require_c_hash=True)
        id_token = self._id_token("nonce")

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_require_c_hash_mismatch_rejected(self) -> None:
        client = self._client(require_c_hash=True)
        id_token = self._id_token("nonce", c_hash=half_hash("another_code"))

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_require_c_hash_matching_accepted(self) -> None:
        client = self._client(require_c_hash=True)

        result = self._finish(client, self._id_token("nonce", c_hash=half_hash("code")), "nonce")

        assert result.claims["sub"] == "subject"

    def test_require_c_hash_without_at_hash_accepted(self) -> None:
        client = self._client(require_c_hash=True)

        result = self._finish(client, self._id_token("nonce", c_hash=half_hash("code")), "nonce")

        assert "at_hash" not in result.claims

    def test_issuer_mismatch_rejected(self) -> None:
        client = self._client()
        id_token = self._id_token("nonce", iss="https://other.example.com")

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    @pytest.mark.parametrize("iss", [ISSUER, "https://other.example.com"])
    def test_key_from_other_issuer_rejected(self, iss: str) -> None:
        client = self._client()
        other_key = _signing_key()  # same kid, different key material
        id_token = self._id_token("nonce", key=other_key, iss=iss)

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    @pytest.mark.parametrize("leeway", [-1, 301, 3600])
    def test_config_rejects_invalid_leeway(self, leeway: int) -> None:
        with pytest.raises(ValidationError, match="leeway"):
            OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, leeway=leeway)

    @pytest.mark.parametrize("algorithms", [[], ["none"], ["HS256"], ["RS256", "FOO"]])
    def test_config_rejects_invalid_allowed_algorithms(self, algorithms: list[str]) -> None:
        with pytest.raises(ValidationError, match="signing algorithm"):
            OidcRpClientConfig(
                client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, allowed_algorithms=algorithms
            )

    @pytest.mark.parametrize("leeway", [0, 60, 300])
    def test_config_accepts_valid_leeway(self, leeway: int) -> None:
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, leeway=leeway)

        assert conf.leeway == leeway

    def test_acr_not_checked_by_default(self) -> None:
        client = self._client(acr_values=["loa3"])
        id_token = self._id_token("nonce", acr="other")

        result = self._finish(client, id_token, "nonce")

        assert result.claims["acr"] == "other"

    def test_require_acr_matching_accepted(self) -> None:
        client = self._client(acr_values=["loa3"], require_acr=True)
        id_token = self._id_token("nonce", acr="loa3")

        result = self._finish(client, id_token, "nonce")

        assert result.claims["acr"] == "loa3"

    @pytest.mark.parametrize("acr", [None, "loa2"])
    def test_require_acr_missing_or_other_rejected(self, acr: str | None) -> None:
        client = self._client(acr_values=["loa3"], require_acr=True)
        claims: dict[str, Any] = {"acr": acr} if acr is not None else {}
        id_token = self._id_token("nonce", **claims)

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_require_acr_uses_accepted_acr_values(self) -> None:
        client = self._client(acr_values=["loa3"], accepted_acr_values=["loa3", "loa4"], require_acr=True)
        id_token = self._id_token("nonce", acr="loa4")

        result = self._finish(client, id_token, "nonce")

        assert result.claims["acr"] == "loa4"

    def test_require_acr_without_values_rejected(self) -> None:
        with pytest.raises(ValidationError, match="require_acr"):
            OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, require_acr=True)

    def test_max_age_missing_auth_time_rejected(self) -> None:
        client = self._client(max_age=300)
        id_token = self._id_token("nonce")

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_max_age_stale_auth_time_rejected(self) -> None:
        client = self._client(max_age=300)
        id_token = self._id_token("nonce", auth_time=int(time.time()) - 3600)

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_max_age_recent_auth_time_accepted(self) -> None:
        client = self._client(max_age=300)
        id_token = self._id_token("nonce", auth_time=int(time.time()) - 10)

        result = self._finish(client, id_token, "nonce")

        assert "auth_time" in result.claims

    @pytest.mark.parametrize("max_age", [0, -1])
    def test_config_rejects_non_positive_max_age(self, max_age: int) -> None:
        with pytest.raises(ValidationError, match="max_age"):
            OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, max_age=max_age)

    def test_hash_config_defaults(self) -> None:
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER)

        assert (conf.require_at_hash, conf.require_c_hash) == (False, False)

    def test_nonce_mismatch(self) -> None:
        client = self._client()
        id_token = self._id_token("other-nonce")

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "expected-nonce")

    def test_wrong_algorithm(self) -> None:
        client = self._client()
        es_key = _signing_key(kid="key1", alg="ES256")
        self.http.add_json(self.metadata["jwks_uri"], es_key.to_public_jwks())

        id_token = self._id_token("nonce", key=es_key)

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_wrong_audience(self) -> None:
        client = self._client()
        id_token = self._id_token("nonce", aud="another_client")

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_unknown_kid(self) -> None:
        client = self._client()
        other_key = _signing_key(kid="unknown")

        id_token = self._id_token("nonce", key=other_key)

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    def test_expired_id_token(self) -> None:
        client = self._client()
        past = int(time.time()) - 3600

        id_token = self._id_token("nonce", exp=past, iat=past - 60)

        with pytest.raises(OidcRpError):
            self._finish(client, id_token, "nonce")

    @pytest.mark.parametrize("amr", ["pwd", ["pwd", "mfa"]])
    def test_string_amr_accepted(self, amr: str | list[str]) -> None:
        """ORCID sends 'amr' as a bare string instead of the array of strings defined by OIDC."""
        client = self._client()

        result = self._finish(client, self._id_token("nonce", amr=amr), "nonce")

        assert result.claims["amr"] == amr

    def test_token_endpoint_error(self) -> None:
        client = self._client()
        self.http.add_json(self.metadata["token_endpoint"], {"error": "invalid_grant"}, status=400)

        with pytest.raises(OidcRpError):
            client.finish("code", redirect_uri=REDIRECT_URI, nonce="nonce", code_verifier=None)

    def test_error_does_not_expose_upstream_details(self) -> None:
        client = self._client()
        self.http.add_json(
            self.metadata["token_endpoint"],
            {"error": "invalid_grant", "error_description": "secret-detail"},
            status=400,
        )

        with pytest.raises(OidcRpError) as exc_info:
            client.finish("code", redirect_uri=REDIRECT_URI, nonce="nonce", code_verifier=None)

        assert "secret-detail" not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__

    def test_value_error_is_wrapped(self) -> None:
        client = self._client()

        with pytest.raises(OidcRpError):
            client.mint_authn_request("not a valid redirect uri")

    def test_unsupported_code_challenge_method(self) -> None:
        with pytest.raises(ValueError, match="Unsupported code_challenge_method"):
            self._client(code_challenge_method="plain")

    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_userinfo(self, method: str) -> None:
        client = self._client(userinfo_method=method)
        result = self._finish(client, self._id_token("nonce"), "nonce")

        userinfo = client.userinfo(result)

        assert userinfo["sub"] == "subject"
        (request,) = self.http.requests_to(self.metadata["userinfo_endpoint"])
        assert request.method == method
        assert request.headers is not None
        assert ("authorization", "Bearer access_token") in request.headers

    def test_userinfo_wrong_sub(self) -> None:
        client = self._client()
        result = self._finish(client, self._id_token("nonce"), "nonce")
        self.http.add_json(self.metadata["userinfo_endpoint"], {"sub": "someone-else"})

        with pytest.raises(OidcRpError):
            client.userinfo(result)

    def _signed_userinfo(
        self, sub: str = "subject", key: SigningKey | None = None, typ: str | None = "userinfo+jwt"
    ) -> None:
        now = int(time.time())
        token = jwt.sign(
            key or self.key, {"iss": ISSUER, "aud": CLIENT_ID, "sub": sub, "iat": now, "name": "Test"}, typ=typ
        )
        self.http.responses[self.metadata["userinfo_endpoint"]] = (200, token.encode(), "application/jwt")

    @pytest.mark.parametrize("method", ["GET", "POST"])
    def test_signed_userinfo_verified_with_trust(self, method: str) -> None:
        client = self._client(userinfo_method=method, userinfo_trust="typed", userinfo_typ="userinfo+jwt")
        result = self._finish(client, self._id_token("nonce"), "nonce")
        self._signed_userinfo()

        userinfo = client.userinfo(result)

        assert userinfo["sub"] == "subject"
        assert userinfo["name"] == "Test"

    @pytest.mark.parametrize("typ", [None, "JWT"])
    def test_id_token_not_accepted_as_signed_userinfo(self, typ: str | None) -> None:
        client = self._client(userinfo_trust="typed", userinfo_typ="userinfo+jwt")
        now = int(time.time())
        claims = {"iss": ISSUER, "sub": "subject", "aud": CLIENT_ID, "exp": now + 300, "iat": now, "nonce": "nonce"}
        id_token = jwt.sign(self.key, claims, typ=typ)
        result = self._finish(client, id_token, "nonce")
        self.http.responses[self.metadata["userinfo_endpoint"]] = (200, id_token.encode(), "application/jwt")

        with pytest.raises(OidcRpError):
            client.userinfo(result)

    def test_signed_userinfo_rejected_without_trust(self) -> None:
        client = self._client()
        result = self._finish(client, self._id_token("nonce"), "nonce")
        self._signed_userinfo()

        with pytest.raises(OidcRpError):
            client.userinfo(result)

    def test_signed_userinfo_wrong_sub(self) -> None:
        client = self._client(userinfo_trust="typed", userinfo_typ="userinfo+jwt")
        result = self._finish(client, self._id_token("nonce"), "nonce")
        self._signed_userinfo(sub="someone-else")

        with pytest.raises(OidcRpError):
            client.userinfo(result)

    def test_signed_userinfo_bad_signature(self) -> None:
        client = self._client(userinfo_trust="typed", userinfo_typ="userinfo+jwt")
        result = self._finish(client, self._id_token("nonce"), "nonce")
        self._signed_userinfo(key=_signing_key(kid="key1"))  # same kid, different key

        with pytest.raises(OidcRpError):
            client.userinfo(result)

    def test_signed_userinfo_wrong_typ(self) -> None:
        client = self._client(userinfo_trust="typed", userinfo_typ="userinfo+jwt")
        result = self._finish(client, self._id_token("nonce"), "nonce")
        self._signed_userinfo(typ="JWT")

        with pytest.raises(OidcRpError):
            client.userinfo(result)

    def test_userinfo_trust_config_validation(self) -> None:
        with pytest.raises(ValidationError, match="requires userinfo_typ"):
            self._client(userinfo_trust="typed")
        with pytest.raises(ValidationError, match="requires userinfo_trust"):
            self._client(userinfo_typ="userinfo+jwt")
        with pytest.raises(ValidationError):
            self._client(userinfo_trust="untyped_shared_key_compat")
        with pytest.raises(ValidationError):
            self._client(userinfo_trust="dedicated_keys")

    @pytest.mark.parametrize("typ", ["JWT", "jwt", "application/jwt"])
    def test_userinfo_typ_must_differ_from_generic_jwt(self, typ: str) -> None:
        with pytest.raises(ValidationError, match="distinct"):
            self._client(userinfo_trust="typed", userinfo_typ=typ)

    def test_userinfo_without_access_token(self) -> None:
        client = self._client()
        result = OidcAuthnResult(claims={"sub": "subject"}, tokens={})

        with pytest.raises(OidcRpError):
            client.userinfo(result)

    def test_end_session(self) -> None:
        client = self._client()

        client.end_session("the-id-token")

        (request,) = self.http.requests_to(f"{ISSUER}/logout")
        assert parse_qs(urlparse(request.url).query) == {"id_token_hint": ["the-id-token"]}

    def test_end_session_without_endpoint(self) -> None:
        del self.metadata["end_session_endpoint"]
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", self.metadata)
        client = self._client()

        with pytest.raises(OidcRpError):
            client.end_session("the-id-token")


def _static_op(issuer: str) -> tuple[StaticHttpClient, dict[str, str]]:
    key = _signing_key()
    metadata = ProviderMetadata(issuer, issuer.rstrip("/")).to_dict()
    metadata["issuer"] = issuer
    http = StaticHttpClient()
    http.add_json(f"{issuer.rstrip('/')}/.well-known/openid-configuration", metadata)
    http.add_json(metadata["jwks_uri"], key.to_public_jwks())
    return http, metadata


class TestIssuerHandling:
    @pytest.mark.parametrize("issuer", ["https://op.example.com", "https://op.example.com/oidc"])
    def test_exact_issuer_discovery_succeeds(self, issuer: str) -> None:
        http, metadata = _static_op(issuer)
        config = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=issuer)

        client = GrindvaktOidcRpClient(config, [REDIRECT_URI], http=http)

        assert client._get_provider().info.issuer == issuer
        assert client.mint_authn_request(REDIRECT_URI).url.startswith(metadata["authorization_endpoint"])

    @pytest.mark.parametrize("issuer", ["https://op.example.com", "https://op.example.com/oidc/"])
    def test_validator_keeps_exact_string(self, issuer: str) -> None:
        config = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=issuer)

        assert config.issuer == issuer

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://op.example.com",
            "https://op.example.com/",
            "https://op.example.com/oidc",
            "https://op.example.com/oidc/",
            "https://op.example.com:8443/oidc",
            "http://localhost",
            "http://LOCALHOST:8080/op",
            "http://127.0.0.1/op",
            "http://[::1]:9000",
        ],
    )
    def test_validator_accepts_and_keeps_valid_issuers(self, issuer: str) -> None:
        assert OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=issuer).issuer == issuer

    @pytest.mark.parametrize(
        "issuer",
        [
            "not a url",
            "http://op.example.com",
            "http://localhost.",
            "http://sub.localhost",
            "ftp://op.example.com",
            "https://user:secret@op.example.com",
            "https://user@op.example.com",
            "https://op.example.com?a=b",
            "https://op.example.com/?",
            "https://op.example.com#frag",
            "https://op.example.com/#",
            "https:///oidc",
            "https://",
        ],
    )
    def test_validator_rejects_invalid_issuers(self, issuer: str) -> None:
        with pytest.raises(ValidationError):
            OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=issuer)

    def test_validator_error_does_not_echo_credentials(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            OidcRpClientConfig(
                client_id=CLIENT_ID, client_secret="secret", issuer="https://user:hunter2@op.example.com"
            )

        assert "hunter2" not in str(exc_info.value)
        assert "hunter2" not in repr(exc_info.value)

    def test_trailing_slash_mismatch_fails_and_logs_issuer(self, caplog: pytest.LogCaptureFixture) -> None:
        # the OP publishes an issuer without trailing slash, but the RP is configured with one
        http, _ = _static_op("https://op.example.com/oidc")
        config = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer="https://op.example.com/oidc/")
        client = GrindvaktOidcRpClient(config, [REDIRECT_URI], http=http)

        with caplog.at_level(logging.ERROR), pytest.raises(OidcRpError):
            client.mint_authn_request(REDIRECT_URI)

        assert "https://op.example.com/oidc/" in caplog.text


class _GatedHttpClient:
    """Wraps a StaticHttpClient; discovery requests signal `entered` and then wait for `gate`."""

    def __init__(self, inner: StaticHttpClient) -> None:
        self.inner = inner
        self.entered = threading.Event()
        self.gate = threading.Event()
        self.gate.set()  # open by default

    def get(self, url: str) -> Any:  # noqa: ANN401
        if url.endswith("/.well-known/openid-configuration"):
            self.entered.set()
            assert self.gate.wait(timeout=30)
        return self.inner.get(url)

    def get_with_headers(self, url: str, headers: list[tuple[str, str]]) -> Any:  # noqa: ANN401
        return self.inner.get_with_headers(url, headers)

    def post_form(self, url: str, form: list[tuple[str, str]], headers: list[tuple[str, str]]) -> Any:  # noqa: ANN401
        return self.inner.post_form(url, form, headers)


class _TimeoutHttpClient(_GatedHttpClient):
    def get(self, url: str) -> Any:  # noqa: ANN401
        self.inner.requests.append(RecordedRequest(method="GET", url=url))
        return 504, b"", None  # what a gateway answers when the OP does not respond in time


class TestDiscoveryConcurrency:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.http, self.metadata = _static_op(ISSUER)
        self.gated = _GatedHttpClient(self.http)
        self.discovery_url = f"{ISSUER}/.well-known/openid-configuration"

    def _client(self, http: Any = None, **config: Any) -> GrindvaktOidcRpClient:  # noqa: ANN401
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, **config)
        return GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=http or self.gated)

    def test_discovery_timeout_fails_and_backs_off(self) -> None:
        timing_out = _TimeoutHttpClient(self.http)
        client = self._client(http=timing_out, discovery_failure_backoff=60)

        for _ in range(2):
            with pytest.raises(OidcRpError):
                client._get_provider()

        assert len(self.http.requests_to(self.discovery_url)) == 1  # second call failed fast, back-off

    def test_cold_start_waiters_do_not_pile_up_discovery_requests(self) -> None:
        client = self._client(discovery_timeout=30)
        self.gated.gate.clear()
        results: list[str] = []
        threads = [
            threading.Thread(target=lambda: results.append(client._get_provider().info.issuer)) for _ in range(4)
        ]
        threads[0].start()
        assert self.gated.entered.wait(timeout=10)
        for thread in threads[1:]:
            thread.start()
        self.gated.gate.set()
        for thread in threads:
            thread.join(timeout=10)

        assert results == [ISSUER] * 4
        assert len(self.http.requests_to(self.discovery_url)) == 1

    def test_cold_start_waiter_gives_up_after_discovery_timeout(self) -> None:
        client = self._client(discovery_timeout=1)
        self.gated.gate.clear()
        first = threading.Thread(target=client._get_provider)
        first.start()
        assert self.gated.entered.wait(timeout=10)

        started = time.monotonic()
        with pytest.raises(OidcRpError):
            client._get_provider()
        assert time.monotonic() - started < 5

        self.gated.gate.set()
        first.join(timeout=10)
        assert len(self.http.requests_to(self.discovery_url)) == 1

    def test_stale_metadata_served_while_another_thread_refreshes(self) -> None:
        now = [1000.0]
        client = self._client(discovery_ttl=100)
        client._clock = lambda: now[0]
        client._get_provider()  # cold start, gate open
        now[0] += 101
        self.gated.entered.clear()
        self.gated.gate.clear()
        refresher = threading.Thread(target=client._get_provider)
        refresher.start()
        assert self.gated.entered.wait(timeout=10)

        # the refresh is in flight and holds the lock: this call must not wait for it
        assert client._get_provider().info.issuer == ISSUER

        self.gated.gate.set()
        refresher.join(timeout=10)
        assert len(self.http.requests_to(self.discovery_url)) == 2

    def test_init_wires_timeouts_and_user_agent(self, mocker: MockerFixture) -> None:
        spy = mocker.patch(
            "eduid.common.clients.oidc_client.grindvakt_client.gv_http.ReqwestClient", wraps=gv_http.ReqwestClient
        )
        config = OidcRpClientConfig(
            client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, discovery_timeout=6, http_request_timeout=40
        )

        init_oidc_rp_client(Flask("test"), "freja_eid", config, [REDIRECT_URI])

        calls = [call.kwargs for call in spy.call_args_list]
        assert {
            "connect_timeout": config.http_connect_timeout,
            "read_timeout": config.http_read_timeout,
            "request_timeout": 40,
            "user_agent": "eduid-freja_eid",
        } in calls
        assert {
            "connect_timeout": 5,
            "read_timeout": 3,
            "request_timeout": 6,
            "user_agent": "eduid-freja_eid",
        } in calls
