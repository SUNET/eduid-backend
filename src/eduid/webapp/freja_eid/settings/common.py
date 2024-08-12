from typing import Union

from pydantic import AnyUrl, BaseModel, Field

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    FrontendActionMixin,
    MagicCookieMixin,
    ProofingConfigMixin,
)

__author__ = "lundberg"


class AuthlibClientConfig(BaseModel):
    client_id: str
    client_secret: str
    issuer: AnyUrl
    code_challenge_method: str = Field(default="S256")
    acr_values: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default=["openid"])


class FrejaEIDClientConfig(AuthlibClientConfig):
    acr_values: list[str] = Field(default=[])
    scopes: list[str] = Field(default=["openid"])
    claims_request: dict[str, Union[None, dict[str, bool]]] = Field(
        default={
            "https://frejaeid.com/oidc/claims/personalIdentityNumber": {"essential": True},
            "https://frejaeid.com/oidc/claims/document": {"essential": True},
            "https://frejaeid.com/oidc/claims/registrationLevel": {"essential": True},
            "https://frejaeid.com/oidc/claims/relyingPartyUserId": {"essential": True},
            "family_name": {"essential": True},
            "given_name": {"essential": True},
            "name": None,
            "https://frejaeid.com/oidc/claims/age": None,
            "https://frejaeid.com/oidc/claims/country": None,
        }
    )


class FrejaEIDConfig(
    EduIDBaseAppConfig,
    AmConfigMixin,
    ProofingConfigMixin,
    ErrorsConfigMixin,
    MagicCookieMixin,
    FrontendActionMixin,
):
    """
    Configuration for the svipe_id app
    """

    app_name: str = "freja_eid"
    freja_eid_client: FrejaEIDClientConfig
