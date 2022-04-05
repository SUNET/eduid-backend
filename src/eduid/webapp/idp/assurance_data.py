"""
Some data structures that causes import loops if they are defined in assurance.py.
"""
from datetime import datetime
from enum import Enum, unique
from typing import Any, Dict

from pydantic import BaseModel

from eduid.userdb.element import ElementKey


@unique
class EduidAuthnContextClass(str, Enum):
    REFEDS_MFA = 'https://refeds.org/profile/mfa'
    REFEDS_SFA = 'https://refeds.org/profile/sfa'
    FIDO_U2F = 'https://www.swamid.se/specs/id-fido-u2f-ce-transports'
    EDUID_MFA = 'https://eduid.se/specs/mfa'
    PASSWORD_PT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'


class AuthnInfo(BaseModel):
    """Information about what AuthnContextClass etc. to put in SAML Authn responses."""

    class_ref: EduidAuthnContextClass
    authn_attributes: Dict[str, Any]  # these are added to the user attributes
    instant: datetime

    def __str__(self):
        return (
            f'<{self.__class__.__name__}: accr={self.class_ref.name}, attributes={self.authn_attributes}, '
            f'instant={self.instant.isoformat()}>'
        )


class UsedWhere(str, Enum):
    REQUEST = 'request'
    SSO = 'SSO session'


class UsedCredential(BaseModel):
    credential_id: ElementKey
    ts: datetime
    source: UsedWhere  # only used for debugging purposes

    def __str__(self) -> str:
        key = str(self.credential_id)
        if len(key) > 24:
            # 24 is length of object-id, webauthn credentials are much longer
            key = key[:21] + '...'
        return (
            f'<{self.__class__.__name__}: credential_id={key}), ts={self.ts.isoformat()}, source={self.source.value}>'
        )
