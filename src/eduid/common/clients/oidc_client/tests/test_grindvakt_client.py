import base64
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask
from pydantic import ValidationError
from pygrindvakt import GrindvaktError, jwt, keys, rp
from pygrindvakt import http as gv_http
from pygrindvakt.keys import SigningKey
from pygrindvakt.metadata import ProviderMetadata
from pytest_mock import MockerFixture
from werkzeug.datastructures import ImmutableMultiDict

from eduid.common.clients.oidc_client.base import (
    ASYMMETRIC_SIGNING_ALGORITHMS,
    OidcAuthnResult,
    OidcRpClientConfig,
    OidcRpError,
    OidcRpIssMismatchError,
)
from eduid.common.clients.oidc_client.grindvakt_client import GrindvaktOidcRpClient, init_oidc_rp_client
from eduid.common.clients.oidc_client.testing import FakeOidcRpClient, RecordedRequest, StaticHttpClient, half_hash

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
        client = self._client(discovery_failure_backoff=1)
        del self.http.responses[f"{ISSUER}/.well-known/openid-configuration"]

        with pytest.raises(OidcRpError):
            client.mint_authn_request(REDIRECT_URI)
        with pytest.raises(OidcRpError, match="code=discovery_backoff"):
            client.mint_authn_request(REDIRECT_URI)
        # the second call failed without any request to the OP
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 1

        # after the back-off a new attempt is made, and succeeds
        time.sleep(1.5)
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", self.metadata)
        assert client.mint_authn_request(REDIRECT_URI).state
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 2

    def test_discovery_refreshed_after_ttl(self) -> None:
        # the OP says max-age=3600, discovery_ttl caps it
        client = self._client(discovery_ttl=1)

        client.mint_authn_request(REDIRECT_URI)
        changed = {**self.metadata, "token_endpoint": f"{ISSUER}/new-token"}
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", changed)
        time.sleep(1.5)

        assert client._get_provider().info.token_endpoint == f"{ISSUER}/new-token"
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 2

    def test_jwks_cache_reused_when_jwks_uri_and_issuer_unchanged(self) -> None:
        client = self._client()
        first = client._get_provider().jwks

        client._discovery.refresh()

        assert client._get_provider().jwks is first
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 2

    def test_jwks_cache_replaced_when_jwks_uri_changes(self) -> None:
        client = self._client()
        first = client._get_provider().jwks
        new_jwks_uri = f"{ISSUER}/new-jwks"
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", {**self.metadata, "jwks_uri": new_jwks_uri})

        client._discovery.refresh()

        refreshed = client._get_provider().jwks
        assert refreshed is not first
        assert refreshed.jwks_uri == new_jwks_uri

    def test_document_with_other_issuer_is_refused_on_refresh(self) -> None:
        # Issuer binding of the cached JwksCache is delegated to pygrindvakt: a document whose issuer differs from the
        # configured one is neither cached nor served, so the key set stays bound to the configured issuer
        client = self._client()
        first = client._get_provider().jwks
        other = "https://other.example.com"
        self.http.add_json(
            f"{ISSUER}/.well-known/openid-configuration",
            {**self.metadata, "issuer": other, "jwks_uri": f"{other}/jwks"},
        )

        with pytest.raises(GrindvaktError):
            client._discovery.refresh()

        jwks = client._get_provider().jwks
        assert jwks is first
        assert jwks.issuer == ISSUER
        assert jwks.jwks_uri == self.metadata["jwks_uri"]

    def test_stale_metadata_used_when_refresh_fails(self) -> None:
        client = self._client(discovery_ttl=1, discovery_failure_backoff=10)
        client.mint_authn_request(REDIRECT_URI)
        del self.http.responses[f"{ISSUER}/.well-known/openid-configuration"]
        time.sleep(1.5)

        with pytest.warns(UserWarning, match="stale discovery metadata"):
            first = client.mint_authn_request(REDIRECT_URI)  # stale metadata, refresh failed
        second = client.mint_authn_request(REDIRECT_URI)  # backing off, no new request
        assert first.state
        assert second.state
        assert len(self.http.requests_to(f"{ISSUER}/.well-known/openid-configuration")) == 2

    def test_init_wires_discovery_cache_config(self, mocker: MockerFixture) -> None:
        spy = mocker.patch(
            "eduid.common.clients.oidc_client.grindvakt_client.rp.DiscoveryCache", wraps=rp.DiscoveryCache
        )

        self._client(discovery_ttl=1800, discovery_timeout=6, discovery_failure_backoff=7, discovery_max_stale=3600)

        assert spy.call_args.args[1] == ISSUER
        assert spy.call_args.kwargs == {
            "default_ttl": 1800,
            "min_ttl": 60,
            "max_ttl": 1800,
            "failure_backoff": 7,
            "stale_on_error": True,
            "max_stale": 3600,
            "fetch_timeout": 6.0,
        }

    def test_jwks_is_fetched_with_the_discovery_http_client(self) -> None:
        # Documents the accepted behaviour: pygrindvakt's DiscoveryCache fetches the JWKS with the client it was given
        discovery_http = StaticHttpClient()
        discovery_http.add_json(f"{ISSUER}/.well-known/openid-configuration", self.metadata)
        discovery_http.add_json(self.metadata["jwks_uri"], self.key.to_public_jwks())
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER)
        client = GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=self.http, discovery_http=discovery_http)

        client._get_provider().jwks.jwks()

        assert len(discovery_http.requests_to(self.metadata["jwks_uri"])) == 1
        assert self.http.requests_to(self.metadata["jwks_uri"]) == []

    def test_compatibility_mismatch_is_logged_once(self, caplog: pytest.LogCaptureFixture) -> None:
        self.metadata["code_challenge_methods_supported"] = ["plain"]
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", self.metadata)
        client = self._client()

        with caplog.at_level(logging.WARNING):
            client.mint_authn_request(REDIRECT_URI)
            client.mint_authn_request(REDIRECT_URI)

        records = [r for r in caplog.records if "compatibility" in r.getMessage()]
        assert len(records) == 1
        assert "S256" in records[0].getMessage()

    def test_get_provider_retakes_info_when_jwks_uri_changed_between_calls(self, mocker: MockerFixture) -> None:
        client = self._client()
        old_info = client._discovery.info()
        new_jwks_uri = f"{ISSUER}/new-jwks"
        self.http.add_json(new_jwks_uri, self.key.to_public_jwks())
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", {**self.metadata, "jwks_uri": new_jwks_uri})
        other = self._client()
        new_info = other._discovery.info()
        new_jwks = other._discovery.jwks()
        assert old_info.jwks_uri != new_jwks_uri
        assert new_jwks.jwks_uri == new_jwks_uri

        fake = mocker.MagicMock()
        fake.info.side_effect = [old_info, new_info]
        fake.jwks.return_value = new_jwks
        client._discovery = fake

        provider = client._get_provider()

        assert fake.info.call_count == 2
        assert fake.jwks.call_count == 2
        assert provider.info is new_info
        assert provider.info.jwks_uri == provider.jwks.jwks_uri == new_jwks_uri

    def test_get_provider_gives_up_when_jwks_uri_keeps_changing(self, mocker: MockerFixture) -> None:
        client = self._client()
        info = client._discovery.info()
        other_jwks = rp.JwksCache(self.http, f"{ISSUER}/other-jwks", ISSUER)
        fake = mocker.MagicMock()
        fake.info.return_value = info
        fake.jwks.return_value = other_jwks
        client._discovery = fake

        with pytest.raises(OidcRpError, match="changed while it was being read"):
            client._get_provider()

        assert fake.info.call_count == fake.jwks.call_count == 3

    def test_compatibility_check_failure_is_logged_once_and_not_fatal(
        self, mocker: MockerFixture, caplog: pytest.LogCaptureFixture
    ) -> None:
        check = mocker.patch(
            "eduid.common.clients.oidc_client.grindvakt_client.rp.check_rp_compatibility",
            side_effect=GrindvaktError("boom"),
        )
        client = self._client()

        with caplog.at_level(logging.ERROR):
            assert client.mint_authn_request(REDIRECT_URI).state
            assert client.mint_authn_request(REDIRECT_URI).state

        assert check.call_count == 1
        records = [r for r in caplog.records if "compatibility check failed" in r.getMessage()]
        assert len(records) == 1
        assert records[0].exc_info is not None

    def test_discovery_backoff_error_is_not_logged_with_traceback(self, caplog: pytest.LogCaptureFixture) -> None:
        client = self._client(discovery_failure_backoff=60)
        del self.http.responses[f"{ISSUER}/.well-known/openid-configuration"]

        with caplog.at_level(logging.ERROR):
            with pytest.raises(OidcRpError):
                client.mint_authn_request(REDIRECT_URI)
            first = [r for r in caplog.records if r.exc_info]
            caplog.clear()
            with pytest.raises(OidcRpError, match="code=discovery_backoff"):
                client.mint_authn_request(REDIRECT_URI)
            second = [r for r in caplog.records if r.exc_info]

        assert len(first) == 1
        assert "OIDC discovery failed" in first[0].getMessage()
        assert second == []

    def test_stale_metadata_not_served_beyond_max_stale(self) -> None:
        client = self._client(discovery_ttl=1, discovery_max_stale=1, discovery_failure_backoff=0)
        client.mint_authn_request(REDIRECT_URI)
        del self.http.responses[f"{ISSUER}/.well-known/openid-configuration"]
        time.sleep(2.5)  # past ttl (1s) + max_stale (1s)

        with pytest.raises(OidcRpError):
            client.mint_authn_request(REDIRECT_URI)

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

    def test_max_age_sent_in_authorization_request(self) -> None:
        client = self._client(max_age=300)

        query = parse_qs(urlparse(client.mint_authn_request(REDIRECT_URI).url).query)

        assert query["max_age"] == ["300"]

    def test_max_age_not_sent_by_default(self) -> None:
        client = self._client()

        query = parse_qs(urlparse(client.mint_authn_request(REDIRECT_URI).url).query)

        assert "max_age" not in query

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

    @pytest.mark.parametrize("trust", [True, False])
    def test_userinfo_typ_passed_to_pygrindvakt_only_with_trust(self, mocker: MockerFixture, trust: bool) -> None:
        # userinfo_trust "typed" requires userinfo_typ in the config, so "trust without typ" is unreachable
        spy = mocker.patch(
            "eduid.common.clients.oidc_client.grindvakt_client.rp.fetch_userinfo", return_value={"sub": "subject"}
        )
        extra = {"userinfo_trust": "typed", "userinfo_typ": "userinfo+jwt"} if trust else {}
        client = self._client(**extra)
        result = self._finish(client, self._id_token("nonce"), "nonce")

        client.userinfo(result)

        kwargs = spy.call_args.kwargs
        if trust:
            assert kwargs["trust"] == "typed"
            assert kwargs["typ"] == "userinfo+jwt"
        else:
            assert "trust" not in kwargs
            assert "typ" not in kwargs

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
            "https://op.example.com/a b",
            " https://op.example.com",
            "https://op.example.com\\x",
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

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://user:hunter2@op.example.com",
            "https://user:hunter2@op.example.com/a b",
            "https://op.example.com/hunter2 x",
        ],
    )
    def test_validator_error_does_not_leak_value(self, issuer: str) -> None:
        with pytest.raises(ValidationError) as exc_info:
            OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=issuer)

        assert "hunter2" not in str(exc_info.value)
        assert "hunter2" not in repr(exc_info.value)

    def test_asymmetric_algorithms_supported_by_pygrindvakt(self) -> None:
        assert set(rp.asymmetric_algorithms()) >= ASYMMETRIC_SIGNING_ALGORITHMS

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
        return 504, b"", None, []  # what a gateway answers when the OP does not respond in time


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
        # one wait for the in-flight refresh, not one per cache lookup
        assert time.monotonic() - started < 1.6

        self.gated.gate.set()
        first.join(timeout=10)
        assert len(self.http.requests_to(self.discovery_url)) == 1

    def test_cold_start_waiter_timeout_is_not_logged_with_traceback(self, caplog: pytest.LogCaptureFixture) -> None:
        client = self._client(discovery_timeout=1)
        self.gated.gate.clear()
        first = threading.Thread(target=client._get_provider)
        first.start()
        assert self.gated.entered.wait(timeout=10)

        with caplog.at_level(logging.ERROR), pytest.raises(OidcRpError, match="code=discovery_fetch_timeout"):
            client._get_provider()

        self.gated.gate.set()
        first.join(timeout=10)
        assert [r for r in caplog.records if r.exc_info and r.thread == threading.main_thread().ident] == []

    def test_stale_metadata_served_after_fetch_timeout_while_refreshing(self) -> None:
        client = self._client(discovery_ttl=1, discovery_timeout=1)
        client._get_provider()  # cold start, gate open
        time.sleep(1.5)
        self.gated.entered.clear()
        self.gated.gate.clear()
        refresher = threading.Thread(target=client._get_provider)
        refresher.start()
        assert self.gated.entered.wait(timeout=10)

        # the refresh is in flight: this call waits at most discovery_timeout, then gets the stale document
        started = time.monotonic()
        with pytest.warns(UserWarning, match="stale discovery metadata"):
            assert client._get_provider().info.issuer == ISSUER
        assert time.monotonic() - started < 5

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


class TestParseCallback:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        self.http = StaticHttpClient()

    def _client(self, **config: Any) -> GrindvaktOidcRpClient:
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, **config)
        return GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=self.http)

    def test_ok_multidict_without_http_request(self) -> None:
        cb = self._client().parse_callback(ImmutableMultiDict({"state": "s1", "code": "c1"}))

        assert cb.state == "s1"
        assert cb.code == "c1"
        assert not cb.is_error
        assert self.http.requests == []

    def test_ok_pairs(self) -> None:
        cb = self._client().parse_callback([("state", "s1"), ("code", "c1")])

        assert (cb.state, cb.code) == ("s1", "c1")

    def test_repr_hides_state_and_code(self) -> None:
        cb = self._client().parse_callback([("state", "secret-state"), ("code", "secret-code")])

        assert "secret-state" not in repr(cb)
        assert "secret-code" not in repr(cb)

    @pytest.mark.parametrize(
        "pairs",
        [
            [("state", "a"), ("state", "b"), ("code", "c")],
            [("state", "a"), ("code", "c"), ("code", "")],
            [("state", "a"), ("error", "access_denied"), ("error_description", "x"), ("error_description", "y")],
            [("state", "a"), ("code", "c"), ("error", "access_denied")],
            [("state", "a")],
            [("state", "a"), ("response", "eyJ.e30.sig")],
        ],
        ids=["dup_state", "dup_code_blank", "dup_error_description", "code_and_error", "neither", "jarm_response"],
    )
    def test_malformed_rejected(self, pairs: list[tuple[str, str]]) -> None:
        client = self._client()

        with pytest.raises(OidcRpError) as exc_info:
            client.parse_callback(pairs)

        assert not isinstance(exc_info.value, OidcRpIssMismatchError)

    def test_wrong_params_type_is_not_wrapped(self) -> None:
        # A plain dict is a programming error, not a malformed response: TypeError must propagate
        client = self._client()

        with pytest.raises(TypeError):
            client.parse_callback({"state": "s", "code": "c"})  # type: ignore[arg-type]

    def test_rejection_log_does_not_echo_values(self, caplog: pytest.LogCaptureFixture) -> None:
        client = self._client()

        with caplog.at_level(logging.DEBUG), pytest.raises(OidcRpError):
            client.parse_callback([("state", "very-secret-1"), ("state", "very-secret-2"), ("code", "c")])

        assert "very-secret" not in caplog.text
        # a shape rejection is reachable without a session: one INFO line, no WARNING
        rejected = [r for r in caplog.records if "authorization response" in r.getMessage()]
        assert [r.levelno for r in rejected] == [logging.INFO]

    def test_iss_match(self) -> None:
        cb = self._client(require_iss=True).parse_callback([("state", "s"), ("code", "c"), ("iss", ISSUER)])

        assert cb.code == "c"

    @pytest.mark.parametrize(
        "iss",
        [
            "https://evil.example.com/op",
            f"{ISSUER}/",
            "HTTPS://op.example.com/op",
            "https://op.example.com/OP",  # case variant of the path
            "https://OP.example.com/op",  # case variant of the host
            "https://\u043ep.example.com/op",  # homoglyph: Cyrillic o in the host
        ],
    )
    def test_iss_mismatch(self, iss: str) -> None:
        for require_iss in (True, False):
            client = self._client(require_iss=require_iss)
            with pytest.raises(OidcRpIssMismatchError, match="iss mismatch"):
                client.parse_callback([("state", "s"), ("code", "c"), ("iss", iss)])

    def test_iss_mismatch_is_logged_as_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        client = self._client()

        with caplog.at_level(logging.DEBUG), pytest.raises(OidcRpIssMismatchError):
            client.parse_callback([("state", "s"), ("code", "c"), ("iss", "https://evil.example.com/op")])

        assert [r.levelno for r in caplog.records if "iss mismatch" in r.getMessage()] == [logging.WARNING]

    def test_missing_iss_required(self) -> None:
        client = self._client(require_iss=True)

        with pytest.raises(OidcRpIssMismatchError, match="iss mismatch"):
            client.parse_callback([("state", "s"), ("code", "c")])

    def test_missing_iss_not_required_by_default(self) -> None:
        assert OidcRpClientConfig(client_id="c", client_secret="s", issuer=ISSUER).require_iss is False

        cb = self._client().parse_callback([("state", "s"), ("code", "c")])

        assert cb.code == "c"

    def test_iss_mismatch_on_error_response(self) -> None:
        client = self._client()

        with pytest.raises(OidcRpIssMismatchError, match="iss mismatch"):
            client.parse_callback([("state", "s"), ("error", "access_denied"), ("iss", "https://evil.example")])

    def test_provider_error_returned(self) -> None:
        cb = self._client().parse_callback([("state", "s"), ("error", "access_denied"), ("iss", ISSUER)])

        assert cb.is_error
        assert cb.error == "access_denied"
        assert cb.error_known is True
        assert cb.code is None

    def test_unknown_error_kept(self) -> None:
        cb = self._client().parse_callback([("state", "s"), ("error", "some_new_error")])

        assert cb.error == "some_new_error"
        assert cb.error_known is False

    @pytest.mark.parametrize(
        "description",
        ["<script>alert(1)</script>", "a\nb\r\nc", "x\x1b[31my", "z" * 3000],
        ids=["html", "nl", "esc", "long"],
    )
    def test_hostile_error_description(self, description: str, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.DEBUG):
            cb = self._client().parse_callback(
                [("state", "s"), ("error", "access_denied"), ("error_description", description)]
            )

        safe = cb.error_description_safe
        assert safe is not None
        assert len(safe) <= 256
        assert not any(ord(ch) < 32 or ord(ch) == 127 for ch in safe)
        assert description not in caplog.text

    def test_compat_advisory_both_directions(self, caplog: pytest.LogCaptureFixture) -> None:
        metadata = ProviderMetadata(ISSUER, ISSUER)
        for advertised, require_iss, expected in (
            (True, False, "consider require_iss=True"),
            (False, True, "callbacks without iss will be rejected"),
        ):
            raw = metadata.to_dict()
            if advertised:
                raw["authorization_response_iss_parameter_supported"] = True
            http = StaticHttpClient()
            http.add_json(f"{ISSUER}/.well-known/openid-configuration", raw)
            http.add_json(raw["jwks_uri"], _signing_key().to_public_jwks())
            conf = OidcRpClientConfig(
                client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER, require_iss=require_iss
            )
            client = GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=http)
            caplog.clear()
            with caplog.at_level(logging.WARNING):
                client.mint_authn_request(REDIRECT_URI)
            assert expected in caplog.text

    def test_compat_advisory_silent_when_consistent(self, caplog: pytest.LogCaptureFixture) -> None:
        raw = ProviderMetadata(ISSUER, ISSUER).to_dict()
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", raw)
        self.http.add_json(raw["jwks_uri"], _signing_key().to_public_jwks())
        with caplog.at_level(logging.WARNING):
            self._client().mint_authn_request(REDIRECT_URI)
        assert "authorization_response_iss_parameter_supported" not in caplog.text

    @pytest.mark.parametrize(
        "pairs",
        [
            [("state", "s"), ("code", "c")],
            [("state", "s"), ("code", "c"), ("iss", ISSUER)],
            [("state", "s"), ("code", "c"), ("iss", "https://evil.example")],
            [("state", "s"), ("state", "t"), ("code", "c")],
            [("state", "s"), ("error", "weird"), ("error_description", "<b>\n")],
        ],
    )
    def test_fake_and_real_parity(self, pairs: list[tuple[str, str]]) -> None:
        real = self._client()
        fake = FakeOidcRpClient(issuer=ISSUER)

        real_error: OidcRpError | None = None
        expected = None
        try:
            expected = real.parse_callback(pairs)
        except OidcRpError as err:
            real_error = err

        if real_error is None:
            assert fake.parse_callback(pairs) == expected
        else:
            with pytest.raises(OidcRpError) as exc_info:
                fake.parse_callback(pairs)
            assert str(exc_info.value) == str(real_error)

    def test_fake_raise_on_parse_callback(self) -> None:
        fake = FakeOidcRpClient(raise_on_parse_callback=OidcRpError("boom"))

        with pytest.raises(OidcRpError, match="boom"):
            fake.parse_callback([("state", "s"), ("code", "c")])

        assert fake.parse_callback_calls == [[("state", "s"), ("code", "c")]]


def _write_ec_pem(path: Path) -> Path:
    key = ec.generate_private_key(ec.SECP256R1())
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return path


def _unverified_claims(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    return claims


class TestClientConfigValidation:
    def test_defaults_unchanged(self) -> None:
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER)

        assert conf.token_endpoint_auth_method == "client_secret_basic"
        assert conf.client_signing_key_path is None
        assert conf.client_signing_key_kid is None
        assert conf.client_signing_alg is None
        assert conf.use_request_object is False

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"client_secret": "secret"},
            {"client_secret": "secret", "token_endpoint_auth_method": "client_secret_post"},
            {"client_secret": "secret", "client_signing_key_path": "/k.pem", "use_request_object": True},
            {"client_secret": "secret", "client_request_object_key_path": "/ro.pem", "use_request_object": True},
            {
                "client_secret": "secret",
                "client_signing_key_path": "/k.pem",
                "client_signing_key_kid": "a",
                "client_request_object_key_path": "/ro.pem",
                "client_request_object_key_kid": "b",
                "client_request_object_signing_alg": "ES256",
                "use_request_object": True,
            },
            {"token_endpoint_auth_method": "private_key_jwt", "client_signing_key_path": "/k.pem"},
            {
                "token_endpoint_auth_method": "private_key_jwt",
                "client_signing_key_path": "/k.pem",
                "client_signing_alg": "ES256",
                "client_signing_key_kid": "k1",
                "use_request_object": True,
            },
        ],
    )
    def test_valid_combinations(self, kwargs: dict[str, Any]) -> None:
        OidcRpClientConfig(client_id=CLIENT_ID, issuer=ISSUER, **kwargs)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {},
            {"token_endpoint_auth_method": "client_secret_post"},
            {"token_endpoint_auth_method": "private_key_jwt"},
            {
                "token_endpoint_auth_method": "private_key_jwt",
                "client_secret": "secret",
                "client_signing_key_path": "/k",
            },
            {"client_secret": "secret", "use_request_object": True},
            {"client_secret": "secret", "client_signing_alg": "ES256"},
            {"client_secret": "secret", "client_signing_key_kid": "k1"},
            {"client_secret": "secret", "client_signing_key_path": "/k", "client_signing_alg": "HS256"},
            {"client_secret": "secret", "token_endpoint_auth_method": "none"},
            {"client_secret": "secret", "client_signing_key_path": "/k", "client_signing_key_kid": ""},
            {"client_secret": "secret", "client_signing_key_path": ""},
            {"client_secret": "secret", "client_signing_key_path": "relative/key.pem"},
            {"client_secret": "secret", "client_request_object_key_path": "key.pem"},
            {"client_secret": "secret", "client_request_object_key_path": "/k", "client_request_object_key_kid": ""},
            {"client_secret": "secret", "client_request_object_key_path": ""},
            {"client_secret": "secret", "client_request_object_key_kid": "k1"},
            {"client_secret": "secret", "client_request_object_signing_alg": "ES256"},
            {
                "client_secret": "secret",
                "client_request_object_key_path": "/k",
                "client_request_object_signing_alg": "none",
            },
            {
                "client_secret": "secret",
                "client_signing_key_path": "/k",
                "client_request_object_key_path": "/k",
            },
            {
                "client_secret": "secret",
                "client_signing_key_path": "/k1",
                "client_signing_key_kid": "same",
                "client_request_object_key_path": "/k2",
                "client_request_object_key_kid": "same",
            },
        ],
    )
    def test_invalid_combinations(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValidationError):
            OidcRpClientConfig(client_id=CLIENT_ID, issuer=ISSUER, **kwargs)


class TestSwedenConnectClient:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path: Path) -> None:
        self.op_key = _signing_key()
        self.pem = _write_ec_pem(tmp_path / "client.pem")
        self.metadata = ProviderMetadata(ISSUER, ISSUER).to_dict()
        self.http = StaticHttpClient()
        self.http.add_json(f"{ISSUER}/.well-known/openid-configuration", self.metadata)
        self.http.add_json(self.metadata["jwks_uri"], self.op_key.to_public_jwks())

    def _client(self, **config: Any) -> GrindvaktOidcRpClient:
        conf = OidcRpClientConfig(
            client_id=CLIENT_ID,
            issuer=ISSUER,
            token_endpoint_auth_method="private_key_jwt",
            client_signing_key_path=self.pem,
            client_signing_key_kid="client-key",
            **config,
        )
        return GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=self.http)

    def test_private_key_jwt_token_request(self) -> None:
        client = self._client()
        data = client.mint_authn_request(REDIRECT_URI)
        now = int(time.time())
        id_token = jwt.sign(
            self.op_key,
            {"iss": ISSUER, "sub": "subject", "aud": CLIENT_ID, "exp": now + 300, "iat": now, "nonce": data.nonce},
        )
        self.http.add_json(
            self.metadata["token_endpoint"],
            {"access_token": "at", "token_type": "Bearer", "id_token": id_token, "expires_in": 3600},
        )

        client.finish("code", redirect_uri=REDIRECT_URI, nonce=data.nonce, code_verifier=data.code_verifier)

        (token_request,) = self.http.requests_to(self.metadata["token_endpoint"])
        assert token_request.form is not None
        form = dict(token_request.form)
        assert "client_secret" not in form
        assert form["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        claims = _unverified_claims(form["client_assertion"])
        assert claims["iss"] == CLIENT_ID
        assert claims["sub"] == CLIENT_ID
        assert claims["aud"] == self.metadata["token_endpoint"]
        assert claims["exp"] > int(time.time())
        assert claims["jti"]
        assert "authorization" not in {name.lower() for name, _ in token_request.headers or []}

    def _pub_jwk(self, path: Path, kid: str) -> dict[str, Any]:
        return keys.signing_key_from_pem(path.read_bytes(), None, kid).public_jwk()

    def _verify(self, token: str, jwk: dict[str, Any]) -> dict[str, Any]:
        return jwt.verify_with_jwk(jwk, token, jwt.Validation().with_allowed_algorithms(["ES256"]))

    def test_separate_request_object_key(self, tmp_path: Path) -> None:
        ro_pem = _write_ec_pem(tmp_path / "ro.pem")
        client = self._client(
            use_request_object=True, client_request_object_key_path=ro_pem, client_request_object_key_kid="ro-key"
        )
        data = client.mint_authn_request(REDIRECT_URI)
        self.http.add_json(self.metadata["token_endpoint"], {"error": "invalid_grant"}, status=400)
        with pytest.raises(OidcRpError):
            client.finish("code", redirect_uri=REDIRECT_URI, nonce=data.nonce, code_verifier=None)

        request_object = parse_qs(urlparse(data.url).query)["request"][0]
        (token_request,) = self.http.requests_to(self.metadata["token_endpoint"])
        assertion = dict(token_request.form or [])["client_assertion"]
        assert jwt.peek_header(request_object)["kid"] == "ro-key"
        assert jwt.peek_header(assertion)["kid"] == "client-key"
        ro_jwk = self._pub_jwk(ro_pem, "ro-key")
        assertion_jwk = self._pub_jwk(self.pem, "client-key")
        assert self._verify(request_object, ro_jwk)["state"] == data.state
        assert self._verify(assertion, assertion_jwk)["sub"] == CLIENT_ID
        with pytest.raises(GrindvaktError):
            self._verify(request_object, assertion_jwk)
        with pytest.raises(GrindvaktError):
            self._verify(assertion, ro_jwk)

    def test_request_object_falls_back_to_client_key(self) -> None:
        data = self._client(use_request_object=True).mint_authn_request(REDIRECT_URI)

        request_object = parse_qs(urlparse(data.url).query)["request"][0]
        assert jwt.peek_header(request_object)["kid"] == "client-key"
        assert self._verify(request_object, self._pub_jwk(self.pem, "client-key"))["nonce"] == data.nonce

    def test_missing_request_object_key_file_is_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match=r"client_request_object_key_path .* is not a regular file"):
            self._client(use_request_object=True, client_request_object_key_path=tmp_path / "nope.pem")

    def test_new_assertion_for_every_token_request(self) -> None:
        client = self._client()
        for _ in range(2):
            self.http.add_json(self.metadata["token_endpoint"], {"error": "invalid_grant"}, status=400)
            with pytest.raises(OidcRpError):
                client.finish("code", redirect_uri=REDIRECT_URI, nonce="n", code_verifier=None)

        requests = self.http.requests_to(self.metadata["token_endpoint"])
        jtis = {_unverified_claims(dict(r.form or [])["client_assertion"])["jti"] for r in requests}
        assert len(jtis) == 2

    def test_request_object_in_authorization_url(self) -> None:
        client = self._client(use_request_object=True)

        data = client.mint_authn_request(REDIRECT_URI)

        query = parse_qs(urlparse(data.url).query)
        claims = _unverified_claims(query["request"][0])
        assert claims["client_id"] == CLIENT_ID
        assert claims["iss"] == CLIENT_ID
        assert claims["aud"] in (ISSUER, self.metadata["authorization_endpoint"])
        assert claims["redirect_uri"] == REDIRECT_URI
        assert claims["state"] == data.state
        assert claims["nonce"] == data.nonce
        assert claims["code_challenge_method"] == "S256"
        assert claims["code_challenge"]

    def test_no_request_object_by_default(self) -> None:
        data = self._client().mint_authn_request(REDIRECT_URI)

        assert "request" not in parse_qs(urlparse(data.url).query)

    def test_client_secret_flow_unchanged(self) -> None:
        conf = OidcRpClientConfig(client_id=CLIENT_ID, client_secret="secret", issuer=ISSUER)
        client = GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=self.http)
        self.http.add_json(self.metadata["token_endpoint"], {"error": "invalid_grant"}, status=400)

        with pytest.raises(OidcRpError):
            client.finish("code", redirect_uri=REDIRECT_URI, nonce="n", code_verifier=None)

        (token_request,) = self.http.requests_to(self.metadata["token_endpoint"])
        assert "client_assertion" not in dict(token_request.form or [])
        assert "authorization" in {name.lower() for name, _ in token_request.headers or []}

    def test_client_secret_post_token_request(self) -> None:
        conf = OidcRpClientConfig(
            client_id=CLIENT_ID,
            client_secret="secret",
            issuer=ISSUER,
            token_endpoint_auth_method="client_secret_post",
        )
        client = GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=self.http)
        self.http.add_json(self.metadata["token_endpoint"], {"error": "invalid_grant"}, status=400)

        with pytest.raises(OidcRpError):
            client.finish("code", redirect_uri=REDIRECT_URI, nonce="n", code_verifier=None)

        (token_request,) = self.http.requests_to(self.metadata["token_endpoint"])
        form = dict(token_request.form or [])
        assert form["client_id"] == CLIENT_ID
        assert form["client_secret"] == "secret"
        assert "client_assertion" not in form
        assert "authorization" not in {name.lower() for name, _ in token_request.headers or []}

    def test_request_object_with_client_secret_basic(self) -> None:
        conf = OidcRpClientConfig(
            client_id=CLIENT_ID,
            client_secret="secret",
            issuer=ISSUER,
            client_signing_key_path=self.pem,
            use_request_object=True,
        )
        client = GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=self.http)

        data = client.mint_authn_request(REDIRECT_URI)
        self.http.add_json(self.metadata["token_endpoint"], {"error": "invalid_grant"}, status=400)
        with pytest.raises(OidcRpError):
            client.finish("code", redirect_uri=REDIRECT_URI, nonce=data.nonce, code_verifier=None)

        assert "request" in parse_qs(urlparse(data.url).query)
        (token_request,) = self.http.requests_to(self.metadata["token_endpoint"])
        assert "client_assertion" not in dict(token_request.form or [])
        assert "authorization" in {name.lower() for name, _ in token_request.headers or []}

    def test_signing_alg_inconsistent_with_key_is_config_error(self) -> None:
        with pytest.raises(ValueError, match="invalid client_signing_key") as excinfo:
            self._client(client_signing_alg="RS256")
        assert "PRIVATE KEY" not in str(excinfo.value)

    def test_empty_client_secret_with_private_key_jwt_is_config_error(self) -> None:
        with pytest.raises(ValueError, match=r"invalid OIDC client configuration: ConfigError: .*client_secret"):
            self._client(client_secret="")

    def test_client_secret_never_in_config_error(self) -> None:
        conf = OidcRpClientConfig.model_construct(
            client_id=CLIENT_ID,
            issuer=ISSUER,
            client_secret="TOP-SECRET-VALUE",
            token_endpoint_auth_method="private_key_jwt",
            client_signing_key_path=self.pem,
            client_signing_key_kid=None,
            client_signing_alg=None,
            client_request_object_key_path=None,
            client_request_object_key_kid=None,
            client_request_object_signing_alg=None,
            use_request_object=False,
            scopes=["openid"],
            code_challenge_method="S256",
        )

        with pytest.raises(ValueError, match="invalid OIDC client configuration") as excinfo:
            GrindvaktOidcRpClient(conf, [REDIRECT_URI], http=self.http)
        assert "TOP-SECRET-VALUE" not in str(excinfo.value)

    def test_key_load_is_logged_without_private_material(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.INFO, logger="eduid.common.clients.oidc_client.grindvakt_client"):
            self._client()

        (message,) = [r.getMessage() for r in caplog.records if "Loaded client_signing_key" in r.getMessage()]
        assert str(self.pem) in message
        assert "kid=client-key" in message
        assert "alg=ES256" in message
        assert "thumbprint=" in message
        assert "PRIVATE" not in message

    def test_key_path_directory_rejected(self, tmp_path: Path) -> None:
        self.pem = tmp_path
        with pytest.raises(ValueError, match="not a regular file"):
            self._client()

    def test_key_path_fifo_rejected_without_blocking(self, tmp_path: Path) -> None:
        if not hasattr(os, "mkfifo"):
            pytest.skip("mkfifo not supported")
        self.pem = tmp_path / "fifo.pem"
        os.mkfifo(self.pem)
        with pytest.raises(ValueError, match="not a regular file"):
            self._client()

    def test_oversized_key_file_rejected(self, tmp_path: Path) -> None:
        self.pem = tmp_path / "big.pem"
        self.pem.write_bytes(b"x" * (64 * 1024 + 1))
        with pytest.raises(ValueError, match="larger than"):
            self._client()

    def test_missing_key_file_is_config_error_at_init(self, tmp_path: Path) -> None:
        self.pem = tmp_path / "missing.pem"

        with pytest.raises(ValueError, match=r"client_signing_key_path .* is not a regular file"):
            self._client()

    def test_invalid_key_file_is_config_error_at_init(self, tmp_path: Path) -> None:
        self.pem = tmp_path / "bad.pem"
        self.pem.write_text("-----BEGIN PRIVATE KEY-----\nSECRETGARBAGE\n-----END PRIVATE KEY-----\n")

        with pytest.raises(ValueError, match="invalid client_signing_key") as excinfo:
            self._client()
        assert "SECRETGARBAGE" not in str(excinfo.value)
