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
    scopes: list[str] = Field(
        default=[
            "openid",
            "profile",
            "https://frejaeid.com/oidc/scopes/personalIdentityNumber",
            "https://frejaeid.com/oidc/scopes/document",
            "https://frejaeid.com/oidc/scopes/registrationLevel",
            "https://frejaeid.com/oidc/scopes/relyingPartyUserId",
        ]
    )
    claims_request: dict[str, Union[None, dict[str, bool]]] = Field(default={})


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
