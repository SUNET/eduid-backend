from typing import Union

from pydantic import Field

from eduid.common.clients.oidc_client.base import AuthlibClientConfig
from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    FrontendActionMixin,
    MagicCookieMixin,
    ProofingConfigMixin,
)

__author__ = "lundberg"


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
            "https://frejaeid.com/oidc/scopes/transactionReference",
            "https://frejaeid.com/oidc/scopes/birthdate",
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
