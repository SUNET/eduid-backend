"""
Configuration (file) handling for the eduID oidceid app.

This app is the OpenID Connect counterpart of samleid: it authenticates against Sweden Connect OpenID Providers
to verify identities with Freja eID, eIDAS (and later BankID).
"""

from typing import Literal, Self

from pydantic import Field, model_validator

from eduid.common.clients.oidc_client.base import OidcRpClientConfig
from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    FrontendActionMixin,
    MagicCookieMixin,
    MsgConfigMixin,
    SwedenConnectProofingConfigMixin,
)

__author__ = "lundberg"


class SwedenConnectOidcClientConfig(OidcRpClientConfig):
    """
    Client config for one Sweden Connect OpenID Provider.

    The authentication context is requested through an essential `acr` claim in the `claims` request parameter,
    never through acr_values. The scopes are extended per proofing method by oidceid.claims.
    """

    token_endpoint_auth_method: Literal["client_secret_basic", "client_secret_post", "private_key_jwt"] = (
        "private_key_jwt"
    )
    scopes: list[str] = Field(default=["openid"])
    # All providers share one redirect URI, so without an authorization response iss (RFC 9207) a mix-up could make
    # the code and PKCE verifier go to the wrong token endpoint before any ID token is validated. Only set this to
    # False for an OP that does not send iss, and then understand that the mix-up protection is gone for that OP.
    require_iss: bool = True
    acr_values: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_no_acr_values(self) -> Self:
        # acr_values would be sent in addition to the essential acr claim (ambiguous, OIDC Core 5.4) and would change
        # the set require_acr accepts, so the requested and the enforced authentication context could diverge.
        if self.acr_values:
            raise ValueError("acr_values must not be set, the required acr is requested through the claims parameter")
        return self


class OidcEidConfig(
    EduIDBaseAppConfig,
    MagicCookieMixin,
    AmConfigMixin,
    ErrorsConfigMixin,
    SwedenConnectProofingConfigMixin,
    FrontendActionMixin,
    MsgConfigMixin,
):
    """
    Configuration for the oidceid app.

    Supports the proofing methods:
    - freja: Swedish NIN via Freja eID (Sweden Connect)
    - eidas: Foreign identity via eIDAS

    The *_idp fields (freja_idp, foreign_identity_idp, bankid_idp, magic_cookie_*_idp) hold the issuer URL
    of one of the configured providers.
    """

    app_name: str = "oidceid"
    # One entry per OpenID Provider, identified by its issuer
    providers: list[SwedenConnectOidcClientConfig] = Field(default_factory=list)
    # Fetch claims from the userinfo endpoint in addition to the ID token
    fetch_userinfo: bool = False
    # Value of the https://id.oidc.se/param/authnProvider request parameter per ProofingMethods value (proxy OPs)
    method_authn_provider: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_idps_match_providers(self) -> Self:
        issuers = [provider.issuer for provider in self.providers]
        duplicates = sorted({issuer for issuer in issuers if issuers.count(issuer) > 1})
        if duplicates:
            raise ValueError(f"provider issuers must be unique, duplicates: {duplicates}")
        idp_fields = (
            "freja_idp",
            "foreign_identity_idp",
            "bankid_idp",
            "magic_cookie_idp",
            "magic_cookie_bankid_idp",
            "magic_cookie_foreign_id_idp",
        )
        for field_name in idp_fields:
            value = getattr(self, field_name)
            if value and value not in issuers:
                raise ValueError(f"{field_name} {value!r} does not match the issuer of any configured provider")
        return self

    @model_validator(mode="after")
    def _check_userinfo_is_signed(self) -> Self:
        # Identity claims (NIN, prid) fetched from userinfo must not be trusted on transport security alone.
        if self.fetch_userinfo:
            unsigned = [provider.issuer for provider in self.providers if provider.userinfo_trust != "typed"]
            if unsigned:
                raise ValueError(
                    f"fetch_userinfo requires userinfo_trust 'typed' on every provider, missing: {unsigned}"
                )
        return self
