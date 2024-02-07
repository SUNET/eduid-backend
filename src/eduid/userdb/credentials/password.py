from __future__ import annotations

from bson import ObjectId
from pydantic import field_validator, Field

from eduid.userdb.credentials import Credential

__author__ = "lundberg"

from eduid.userdb.element import ElementKey


class Password(Credential):
    credential_id: str = Field(alias="id")
    salt: str
    is_generated: bool = False

    @field_validator("credential_id", mode="before")
    @classmethod
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
