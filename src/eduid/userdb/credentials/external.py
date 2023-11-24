from __future__ import annotations

from enum import Enum
from typing import Any, Mapping, Optional

from bson import ObjectId
from pydantic import Field, validator

from eduid.userdb.credentials import Credential
from eduid.userdb.element import ElementKey
from eduid.userdb.util import objectid_str


class TrustFramework(str, Enum):
    SWECONN = "SWECONN"
    EIDAS = "EIDAS"
    SVIPE = "SVIPE"
    BANKID = "BANKID"


class ExternalCredential(Credential):
    credential_id: str = Field(alias="id", default_factory=objectid_str)
    framework: TrustFramework

    @validator("credential_id", pre=True)
    def credential_id_objectid(cls, v):
        """Turn ObjectId into string"""
        if isinstance(v, ObjectId):
            v = str(v)
        if not isinstance(v, str):
            raise TypeError("must be a string or ObjectId")
        return v

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key.
        """
        return ElementKey(self.credential_id)


class SwedenConnectCredential(ExternalCredential):
    framework: TrustFramework = Field(default=TrustFramework.SWECONN, const=True)
    # To be technology neutral, we don't want to store e.g. the SAML authnContextClassRef in the database,
    # and mapping a level to an authnContextClassRef really ought to be dependent on configuration matching
    # the IdP:s expected values at a certain time. Such configuration is better to have in the SP than in
    # the database layer.
    level: str  # a value like "loa3", "eidas_sub", ...


class EidasCredential(ExternalCredential):
    framework: TrustFramework = Field(default=TrustFramework.EIDAS, const=True)
    # To be technology neutral, we don't want to store e.g. the SAML authnContextClassRef in the database,
    # and mapping a level to an authnContextClassRef really ought to be dependent on configuration matching
    # the IdP:s expected values at a certain time. Such configuration is better to have in the SP than in
    # the database layer.
    level: str  # a value like "loa3", "eidas_sub", ...


class BankIDCredential(ExternalCredential):
    framework: TrustFramework = Field(default=TrustFramework.BANKID, const=True)
    # To be technology neutral, we don't want to store e.g. the SAML authnContextClassRef in the database,
    # and mapping a level to an authnContextClassRef really ought to be dependent on configuration matching
    # the IdP:s expected values at a certain time. Such configuration is better to have in the SP than in
    # the database layer.
    level: str  # a value like "loa3", "eidas_sub", ...


def external_credential_from_dict(data: Mapping[str, Any]) -> Optional[ExternalCredential]:
    if data["framework"] == TrustFramework.SWECONN.value:
        return SwedenConnectCredential.from_dict(data)
    if data["framework"] == TrustFramework.EIDAS.value:
        return EidasCredential.from_dict(data)
    if data["framework"] == TrustFramework.BANKID.value:
        return BankIDCredential.from_dict(data)
    return None
