"""
Configuration (file) handling for the eduID samleid app.

This app combines the functionality of eidas and bankid apps into a unified
SAML-based identity proofing service.
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


class SamlEidConfig(
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
    Configuration for the samleid app.

    Supports three proofing methods:
    - freja: Swedish NIN via Freja eID (Sweden Connect)
    - bankid: Swedish NIN via BankID (Sweden Connect)
    - eidas: Foreign identity via eIDAS
    """

    app_name: str = "samleid"
