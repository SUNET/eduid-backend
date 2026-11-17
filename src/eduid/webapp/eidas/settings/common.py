"""
Configuration (file) handling for the eduID eidas app.
"""

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


class EidasConfig(
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

    app_name: str = "eidas"
