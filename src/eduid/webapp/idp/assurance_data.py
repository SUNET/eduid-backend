"""
Some data structures that causes import loops if they are defined in assurance.py.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

from eduid.common.models.saml2 import EduidAuthnContextClass


class SwamidAssurance(StrEnum):
    SWAMID_AL1 = "http://www.swamid.se/policy/assurance/al1"
    SWAMID_AL2 = "http://www.swamid.se/policy/assurance/al2"
    SWAMID_AL3 = "http://www.swamid.se/policy/assurance/al3"
    REFEDS_ASSURANCE = "https://refeds.org/assurance"
    REFEDS_IAP_HIGH = "https://refeds.org/assurance/IAP/high"
    REFEDS_IAP_LOW = "https://refeds.org/assurance/IAP/low"
    REFEDS_IAP_MEDIUM = "https://refeds.org/assurance/IAP/medium"
    REFEDS_EPPN_UNIQUE = "https://refeds.org/assurance/ID/eppn-unique-no-reassign"
    REFEDS_ID_UNIQUE = "https://refeds.org/assurance/ID/unique"
    REFEDS_PROFILE_CAPPUCCINO = "https://refeds.org/assurance/profile/cappuccino"
    REFEDS_PROFILE_ESPRESSO = "https://refeds.org/assurance/profile/espresso"


class SwedenConnectAssurance(StrEnum):
    LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2"
    LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3"
    UNCERTIFIED_LOA3 = "http://id.swedenconnect.se/loa/1.0/uncertified-loa3"


class AuthnInfo(BaseModel):
    """Information about what AuthnContextClass etc. to put in SAML Authn responses."""

    class_ref: EduidAuthnContextClass
    authn_attributes: dict[str, Any]  # these are added to the user attributes
    instant: datetime

    def __str__(self) -> str:
        return (
            f"<{self.__class__.__name__}: accr={self.class_ref.name}, attributes={self.authn_attributes}, "
            f"instant={self.instant.isoformat()}>"
        )
