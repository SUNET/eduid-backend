"""
Some data structures that causes import loops if they are defined in assurance.py.
"""
from datetime import datetime
from enum import Enum, unique
from typing import Any

from pydantic import BaseModel

from eduid.userdb.element import ElementKey


@unique
class EduidAuthnContextClass(str, Enum):
    REFEDS_MFA = "https://refeds.org/profile/mfa"
    REFEDS_SFA = "https://refeds.org/profile/sfa"
    FIDO_U2F = "https://www.swamid.se/specs/id-fido-u2f-ce-transports"
    EDUID_MFA = "https://eduid.se/specs/mfa"
    PASSWORD_PT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"


class SwamidAssurance(str, Enum):
    SWAMID_AL1 = "http://www.swamid.se/policy/assurance/al1"
    SWAMID_AL2 = "http://www.swamid.se/policy/assurance/al2"
    SWAMID_AL3 = "http://www.swamid.se/policy/assurance/al3"
    SWAMID_AL2_MFA_HIGH = "http://www.swamid.se/policy/authentication/swamid-al2-mfa-hi"
    REFEDS_ASSURANCE = "https://refeds.org/assurance"
    REFEDS_IAP_HIGH = "https://refeds.org/assurance/IAP/high"
    REFEDS_IAP_LOW = "https://refeds.org/assurance/IAP/low"
    REFEDS_IAP_MEDIUM = "https://refeds.org/assurance/IAP/medium"
    REFEDS_EPPN_UNIQUE = "https://refeds.org/assurance/ID/eppn-unique-no-reassign"
    REFEDS_ID_UNIQUE = "https://refeds.org/assurance/ID/unique"


class AuthnInfo(BaseModel):
    """Information about what AuthnContextClass etc. to put in SAML Authn responses."""

    class_ref: EduidAuthnContextClass
    authn_attributes: dict[str, Any]  # these are added to the user attributes
    instant: datetime

    def __str__(self):
        return (
            f"<{self.__class__.__name__}: accr={self.class_ref.name}, attributes={self.authn_attributes}, "
            f"instant={self.instant.isoformat()}>"
        )


class UsedWhere(str, Enum):
    REQUEST = "request"
    SSO = "SSO session"


class UsedCredential(BaseModel):
    credential_id: ElementKey
    ts: datetime
    source: UsedWhere  # only used for debugging purposes

    def __str__(self) -> str:
        key = str(self.credential_id)
        if len(key) > 24:
            # 24 is length of object-id, webauthn credentials are much longer
            key = key[:21] + "..."
        return (
            f"<{self.__class__.__name__}: credential_id={key}), ts={self.ts.isoformat()}, source={self.source.value}>"
        )
