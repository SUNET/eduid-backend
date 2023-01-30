# -*- coding: utf-8 -*-

from typing import List

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
    acr_values: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default=["openid"])


class SvipeClientConfig(AuthlibClientConfig):
    acr_values: List[str] = Field(default=["face_present"])
    scopes: List[str] = Field(
        default=[
            "openid",
            "birthdate",
            "com.svipe:document_administrative_number",
            "com.svipe:document_expiry_date",
            "com.svipe:document_issuing_country",
            "com.svipe:document_nationality",
            "com.svipe:document_number",
            "com.svipe:document_type_sdn_en",
            "com.svipe:meta_transaction_id",
            "com.svipe:svipeid",
            "family_name",
            "given_name",
            "name",
        ]
    )


class SvipeIdConfig(
    EduIDBaseAppConfig, AmConfigMixin, MsgConfigMixin, ProofingConfigMixin, ErrorsConfigMixin, MagicCookieMixin
):
    """
    Configuration for the svipe_id app
    """

    app_name: str = "svipe_id"
    svipe_client: SvipeClientConfig
