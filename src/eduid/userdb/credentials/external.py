from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Mapping, Optional

from bson import ObjectId
from pydantic import Field, validator

from eduid.userdb.credentials import Credential
from eduid.userdb.element import ElementKey
from eduid.userdb.util import objectid_str


class TrustFramework(str, Enum):
    SWECONN = 'SWECONN'
    EIDAS = 'EIDAS'


class ExternalCredential(Credential):
    credential_id: str = Field(alias='id', default_factory=objectid_str)
    framework: TrustFramework

    @validator('credential_id', pre=True)
    def credential_id_objectid(cls, v):
        """Turn ObjectId into string"""
        if isinstance(v, ObjectId):
            v = str(v)
        if not isinstance(v, str):
            raise TypeError('must be a string or ObjectId')
        return v

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key.
        """
        return ElementKey(self.credential_id)

    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        data['framework'] = self.framework.value
        return data


class SwedenConnectCredential(ExternalCredential):
    framework: TrustFramework = Field(default=TrustFramework.SWECONN, const=True)
    # To be technology neutral, we don't want to store e.g. the SAML authnContextClassRef in the database,
    # and mapping a level to an authnContextClassRef really ought to be dependent on configuration matching
    # the IdP:s expected values at a certain time. Such configuration is better to have in the SP than in
    # the database layer.
    level: str  # a value like "loa3", "eidas_sub", ...


def external_credential_from_dict(data: Mapping[str, Any]) -> Optional[ExternalCredential]:
    if data['framework'] == TrustFramework.SWECONN.value:
        return SwedenConnectCredential.from_dict(data)
    return None
