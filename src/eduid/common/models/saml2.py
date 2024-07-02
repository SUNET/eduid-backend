# -*- coding: utf-8 -*-

from enum import Enum, unique

__author__ = "lundberg"


@unique
class EduidAuthnContextClass(str, Enum):
    DIGG_LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2"
    REFEDS_MFA = "https://refeds.org/profile/mfa"
    REFEDS_SFA = "https://refeds.org/profile/sfa"
    FIDO_U2F = "https://www.swamid.se/specs/id-fido-u2f-ce-transports"
    EDUID_MFA = "https://eduid.se/specs/mfa"
    PASSWORD_PT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    NOT_IMPLEMENTED = "not implemented"
