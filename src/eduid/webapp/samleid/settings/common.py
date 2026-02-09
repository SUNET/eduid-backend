"""
Configuration (file) handling for the eduID samleid app.

This app combines the functionality of eidas and bankid apps into a unified
SAML-based identity proofing service.
"""

from collections.abc import Mapping
from functools import cached_property

from pydantic import Field

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    FrontendActionMixin,
    MagicCookieMixin,
    MsgConfigMixin,
    ProofingConfigMixin,
    Pysaml2SPConfigMixin,
)


class SamlEidConfig(
    EduIDBaseAppConfig,
    MagicCookieMixin,
    AmConfigMixin,
    ErrorsConfigMixin,
    ProofingConfigMixin,
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

    # Federation config - union of eidas and bankid LOA mappings
    loa_authn_context_map: dict[str, str] = Field(
        default={
            # Sweden Connect LOA levels
            "loa1": "http://id.elegnamnden.se/loa/1.0/loa1",
            "loa2": "http://id.elegnamnden.se/loa/1.0/loa2",
            "loa3": "http://id.elegnamnden.se/loa/1.0/loa3",
            "uncertified-loa3": "http://id.swedenconnect.se/loa/1.0/uncertified-loa3",
            "loa4": "http://id.elegnamnden.se/loa/1.0/loa4",
            # eIDAS LOA levels
            "eidas-low": "http://id.elegnamnden.se/loa/1.0/eidas-low",
            "eidas-sub": "http://id.elegnamnden.se/loa/1.0/eidas-sub",
            "eidas-high": "http://id.elegnamnden.se/loa/1.0/eidas-high",
            "eidas-nf-low": "http://id.elegnamnden.se/loa/1.0/eidas-nf-low",
            "eidas-nf-sub": "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
            "eidas-nf-high": "http://id.elegnamnden.se/loa/1.0/eidas-nf-high",
        }
    )

    @cached_property
    def authn_context_loa_map(self) -> dict[str, str]:
        return {value: key for key, value in self.loa_authn_context_map.items()}

    # Staging nin map (for eidas compatibility)
    nin_attribute_map: Mapping[str, str] = Field(
        default={
            #  'test nin': 'user nin'
        }
    )

    # magic cookie IdP is used for integration tests when magic cookie is set
    magic_cookie_idp: str | None = None
    magic_cookie_foreign_id_idp: str | None = None

    # Feature flags
    allow_eidas_credential_verification: bool = False
