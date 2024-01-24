"""
Configuration (file) handling for the eduID eidas app.
"""

from typing import Optional

from pydantic import Field

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    MagicCookieMixin,
    ProofingConfigMixin,
    Pysaml2SPConfigMixin,
)


class BankIDConfig(
    EduIDBaseAppConfig,
    MagicCookieMixin,
    AmConfigMixin,
    ErrorsConfigMixin,
    ProofingConfigMixin,
    Pysaml2SPConfigMixin,
):
    """
    Configuration for the eidas app
    """

    app_name: str = "bankid"

    authn_service_url: str

    # Federation config
    authentication_context_map: dict[str, str] = Field(
        default={
            "uncertified-loa3": "http://id.swedenconnect.se/loa/1.0/uncertified-loa3",
        }
    )
    # magic cookie IdP is used for integration tests when magic cookie is set
    magic_cookie_idp: Optional[str] = None
    magic_cookie_foreign_id_idp: Optional[str] = None
