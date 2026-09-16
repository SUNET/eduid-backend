from collections.abc import Mapping
from typing import Any

from authlib.integrations.base_client import OAuthError
from authlib.integrations.flask_client import OAuth
from flask import Flask

from eduid.common.clients.oidc_client.base import OidcRpClientConfig, OidcRpError, OidcStateCache

__author__ = "lundberg"


class AuthlibOidcRpClient:
    """OidcRpClient implementation backed by authlib's Flask OAuth client."""

    def __init__(self, client: Any) -> None:  # noqa: ANN401
        self._client = client

    def authorization_url(self, redirect_uri: str, extra_params: Mapping[str, str] | None = None) -> str:
        try:
            response = self._client.authorize_redirect(redirect_uri=redirect_uri, **(extra_params or {}))
        except OAuthError as err:
            raise OidcRpError(str(err)) from err
        location: str = response.headers["Location"]
        return location

    def fetch_token(self) -> dict[str, Any]:
        try:
            token_response: dict[str, Any] = self._client.authorize_access_token()
        except OAuthError as err:
            raise OidcRpError(str(err)) from err
        return token_response

    def userinfo(self) -> dict[str, Any]:
        try:
            userinfo_response: dict[str, Any] = self._client.userinfo()
        except OAuthError as err:
            raise OidcRpError(str(err)) from err
        return userinfo_response

    def server_metadata(self) -> Mapping[str, Any]:
        try:
            metadata: Mapping[str, Any] = self._client.load_server_metadata()
        except OAuthError as err:
            raise OidcRpError(str(err)) from err
        return metadata

    def end_session(self, id_token: str) -> None:
        try:
            metadata = self._client.load_server_metadata()
            self._client.get(metadata.get("end_session_endpoint"), params={"id_token_hint": id_token})
        except OAuthError as err:
            raise OidcRpError(str(err)) from err


def init_oidc_rp_client(
    app: Flask, name: str, config: OidcRpClientConfig, cache: OidcStateCache
) -> AuthlibOidcRpClient:
    """
    Set up an authlib-backed OIDC RP client and register it with the given Flask app.

    :param app: the Flask app to register the client with
    :param name: the name to register the client under (also used as a cache key prefix by authlib)
    :param config: the OIDC RP client configuration
    :param cache: the state/nonce cache to use
    """
    oauth = OAuth(app, cache=cache)
    client_kwargs = {}
    if config.scopes:
        client_kwargs["scope"] = " ".join(config.scopes)
    if config.code_challenge_method:
        client_kwargs["code_challenge_method"] = config.code_challenge_method
    authorize_params = {}
    if config.acr_values:
        authorize_params["acr_values"] = " ".join(config.acr_values)
    oauth.register(  # type: ignore[no-untyped-call]
        name=name,
        client_id=config.client_id,
        client_secret=config.client_secret,
        client_kwargs=client_kwargs,
        authorize_params=authorize_params,
        server_metadata_url=f"{config.issuer}/.well-known/openid-configuration",
    )
    client = getattr(oauth, name)
    return AuthlibOidcRpClient(client)
