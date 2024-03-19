"""
Configuration (file) handling for the eduID eidas app.
"""

from typing import Mapping, Optional

from pydantic import Field

from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    ErrorsConfigMixin,
    MagicCookieMixin,
    ProofingConfigMixin,
    Pysaml2SPConfigMixin,
)


class EidasConfig(
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

    app_name: str = "eidas"

    token_service_url: str

    token_verify_redirect_url: str  # TODO: remove when old views are gone
    identity_verify_redirect_url: str  # TODO: remove when old views are gone

    # Federation config
    authentication_context_map: dict[str, str] = Field(
        default={
            "loa1": "http://id.elegnamnden.se/loa/1.0/loa1",
            "loa2": "http://id.elegnamnden.se/loa/1.0/loa2",
            "loa3": "http://id.elegnamnden.se/loa/1.0/loa3",
            "uncertified-loa3": "http://id.swedenconnect.se/loa/1.0/uncertified-loa3",
            "loa4": "http://id.elegnamnden.se/loa/1.0/loa4",
            "eidas-low": "http://id.elegnamnden.se/loa/1.0/eidas-low",
            "eidas-sub": "http://id.elegnamnden.se/loa/1.0/eidas-sub",
            "eidas-high": "http://id.elegnamnden.se/loa/1.0/eidas-high",
            "eidas-nf-low": "http://id.elegnamnden.se/loa/1.0/eidas-nf-low",
            "eidas-nf-sub": "http://id.elegnamnden.se/loa/1.0/eidas-nf-sub",
            "eidas-nf-high": "http://id.elegnamnden.se/loa/1.0/eidas-nf-high",
        }
    )

    # Staging nin map
    nin_attribute_map: Mapping[str, str] = Field(
        default={
            #  'test nin': 'user nin'
        }
    )
    # magic cookie IdP is used for integration tests when magic cookie is set
    magic_cookie_idp: Optional[str] = None
    magic_cookie_foreign_id_idp: Optional[str] = None
