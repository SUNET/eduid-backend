from __future__ import annotations

import copy
import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

import bson
from pydantic import BaseModel, ConfigDict, Field

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.security.element import CodeElement

__author__ = "lundberg"

from eduid.userdb.util import utc_now

TPasswordResetStateSubclass = TypeVar("TPasswordResetStateSubclass", bound="PasswordResetState")


class PasswordResetState(BaseModel):
    eppn: str = Field(alias="eduPersonPrincipalName")
    state_id: bson.ObjectId = Field(default_factory=lambda: bson.ObjectId(), alias="_id")
    created_ts: datetime.datetime = Field(default_factory=lambda: utc_now())
    modified_ts: datetime.datetime | None = None
    extra_security: dict[str, Any] | None = None
    generated_password: str | None = None
    model_config = ConfigDict(
        populate_by_name=True, validate_assignment=True, extra="forbid", arbitrary_types_allowed=True
    )

    # @deprecated("Remove once the password reset views are served from their own webapp")
    # def __post_init__(self):
    #    self.reference = str(self.id)

    def __str__(self):
        return f"<eduID {self.__class__.__name__!s}: {self.eppn!s}>"

    @property
    def reference(self) -> str:
        return str(self.state_id)

    def to_dict(self) -> TUserDbDocument:
        """Convert state to a dict in eduid format, that can be used to reconstruct the state later."""
        data = self.dict(exclude_none=True)
        data = self._to_dict_transform(data)
        return TUserDbDocument(data)

    @classmethod
    def from_dict(cls: type[TPasswordResetStateSubclass], data: Mapping[str, Any]) -> TPasswordResetStateSubclass:
        _data = dict(copy.deepcopy(data))  # to not modify callers data
        _data = cls._from_dict_transform(_data)
        return cls(**_data)

    @classmethod
    def _from_dict_transform(cls: type[TPasswordResetStateSubclass], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        if "reference" in data:
            data.pop("reference")
        return data

    @classmethod
    def _to_dict_transform(cls, data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        data["eduPersonPrincipalName"] = data.pop("eppn")
        data["_id"] = data.pop("state_id")
        return data


class PasswordResetEmailState(PasswordResetState):
    email_address: str
    email_code: CodeElement


class PasswordResetEmailAndPhoneState(PasswordResetEmailState):
    phone_number: str
    phone_code: CodeElement

    @classmethod
    def from_email_state(
        cls, email_state: PasswordResetEmailState, phone_number: str, phone_code: str, application="security"
    ) -> PasswordResetEmailAndPhoneState:
        data = email_state.to_dict()
        data["phone_number"] = phone_number
        data["phone_code"] = CodeElement(created_by=application, code=phone_code)
        return cls.from_dict(data=data)
