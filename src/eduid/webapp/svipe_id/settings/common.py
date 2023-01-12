from pydantic import AnyUrl, BaseModel, Field

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    MagicCookieMixin,
    MsgConfigMixin,
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


class SvipeIdConfig(
    EduIDBaseAppConfig, AmConfigMixin, MsgConfigMixin, ProofingConfigMixin, ErrorsConfigMixin, MagicCookieMixin
):
    """
    Configuration for the svipe_id app
    """

    app_name: str = "svipe_id"
    svipe_client: AuthlibClientConfig
