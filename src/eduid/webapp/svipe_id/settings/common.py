from typing import Union

from pydantic import AnyUrl, BaseModel, Field

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


class SvipeClientConfig(AuthlibClientConfig):
    acr_values: list[str] = Field(default=["face_present"])
    scopes: list[str] = Field(default=["openid"])
    claims_request: dict[str, Union[None, dict[str, bool]]] = Field(
        default={
            "birthdate": {"essential": True},
            "com.svipe:document_administrative_number": {"essential": True},
            "com.svipe:document_expiry_date": {"essential": True},
            "com.svipe:document_issuing_country": {"essential": True},
            "com.svipe:document_nationality": {"essential": True},
            "com.svipe:document_number": {"essential": True},
            "com.svipe:document_type_sdn_en": {"essential": True},
            "com.svipe:meta_transaction_id": {"essential": True},
            "com.svipe:svipeid": {"essential": True},
            "family_name": {"essential": True},
            "given_name": {"essential": True},
            "name": None,
        }
    )


class SvipeIdConfig(
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

    app_name: str = "svipe_id"
    svipe_client: SvipeClientConfig
