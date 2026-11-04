"""
Configuration (file) handling for the eduID eidas app.
"""

from pydantic import Field

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    FrontendActionMixin,
    MagicCookieMixin,
    MsgConfigMixin,
    Pysaml2SPConfigMixin,
    SwedenConnectProofingConfigMixin,
)


class BankIDConfig(
    EduIDBaseAppConfig,
    MagicCookieMixin,
    AmConfigMixin,
    ErrorsConfigMixin,
    SwedenConnectProofingConfigMixin,
    Pysaml2SPConfigMixin,
    FrontendActionMixin,
    MsgConfigMixin,
):
    """
    Configuration for the eidas app
    """

    app_name: str = "bankid"

    # Federation config
    loa_authn_context_map: dict[str, str] = Field(
        default={
            "uncertified-loa3": "http://id.swedenconnect.se/loa/1.0/uncertified-loa3",
        }
    )
