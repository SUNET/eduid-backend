from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Literal

from bson import ObjectId
from pydantic import Field, field_validator

from eduid.userdb.credentials import Credential
from eduid.userdb.element import ElementKey
from eduid.userdb.util import objectid_str


class TrustFramework(StrEnum):
    SWECONN = "SWECONN"
    EIDAS = "EIDAS"
    SVIPE = "SVIPE"
    BANKID = "BANKID"
    FREJA = "FREJA"


class ExternalCredential(Credential):
    credential_id: str = Field(alias="id", default_factory=objectid_str)
    framework: TrustFramework

    @field_validator("credential_id", mode="before")
    @classmethod
    def credential_id_objectid(cls, v: object) -> str:
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


# To be technology neutral, we don't want to store e.g. the SAML authnContextClassRef in the database,
# and mapping a level to an authnContextClassRef really ought to be dependent on configuration matching
# the IdP:s expected values at a certain time. Such configuration is better to have in the SP than in
# the database layer.
class SwedenConnectCredential(ExternalCredential):
    framework: Literal[TrustFramework.SWECONN] = TrustFramework.SWECONN
    level: str  # a value like "loa3", "eidas_sub", ...


class EidasCredential(ExternalCredential):
    framework: Literal[TrustFramework.EIDAS] = TrustFramework.EIDAS
    level: str  # a value like "loa3", "eidas_sub", ...


class BankIDCredential(ExternalCredential):
    framework: Literal[TrustFramework.BANKID] = TrustFramework.BANKID
    level: str  # a value like "loa3", "eidas_sub", ...


class FrejaCredential(ExternalCredential):
    framework: Literal[TrustFramework.FREJA] = TrustFramework.FREJA
    level: str  # a value like "loa3", "eidas_sub", ...


def external_credential_from_dict(data: Mapping[str, Any]) -> ExternalCredential | None:
    match data["framework"]:
        case TrustFramework.SWECONN.value:
            return SwedenConnectCredential.from_dict(data)
        case TrustFramework.EIDAS.value:
            return EidasCredential.from_dict(data)
        case TrustFramework.BANKID.value:
            return BankIDCredential.from_dict(data)
        case TrustFramework.FREJA.value:
            return FrejaCredential.from_dict(data)
        case _:
            return None
