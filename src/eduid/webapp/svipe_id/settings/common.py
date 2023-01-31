from typing import Any, Optional, Union

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


class SvipeClientConfig(AuthlibClientConfig):
    acr_values: list[str] = Field(default=["face_present"])
    scopes: list[str] = Field(default=["openid"])
    claims_request: dict[str, dict[str, Union[bool, None]]] = Field(
        # TODO: All claims except name should be required ({"essential": True} instead of None)
        #       but I can't get it to work
        default={
            "birthdate": None,
            "com.svipe:document_administrative_number": None,
            "com.svipe:document_expiry_date": None,
            "com.svipe:document_issuing_country": None,
            "com.svipe:document_nationality": None,
            "com.svipe:document_number": None,
            "com.svipe:document_type_sdn_en": None,
            "com.svipe:meta_transaction_id": None,
            "com.svipe:svipeid": None,
            "family_name": None,
            "given_name": None,
            "name": None,
        }
    )


class SvipeIdConfig(
    EduIDBaseAppConfig, AmConfigMixin, MsgConfigMixin, ProofingConfigMixin, ErrorsConfigMixin, MagicCookieMixin
):
    """
    Configuration for the svipe_id app
    """

    app_name: str = "svipe_id"
    svipe_client: SvipeClientConfig
