from __future__ import annotations

import builtins
import uuid
from abc import ABC
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from eduid.common.models.scim_base import EmailType, PhoneNumberType, WeakVersion
from eduid.userdb.util import utc_now

__author__ = "lundberg"


@dataclass
class ScimApiResourceBase(ABC):
    """The elements common to all SCIM resource database objects"""

    scim_id: UUID = field(default_factory=lambda: uuid.uuid4())
    external_id: str | None = None
    version: WeakVersion = field(default_factory=lambda: WeakVersion())
    created: datetime = field(default_factory=lambda: utc_now())
    last_modified: datetime = field(default_factory=lambda: utc_now())


@dataclass(frozen=True)
class ScimApiProfile:
    attributes: dict[str, Any] = field(default_factory=dict)
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls: type[ScimApiProfile], data: Mapping[str, Any]) -> ScimApiProfile:
        _attributes = data.get("attributes", {})
        _data = data.get("data", {})
        return cls(attributes=_attributes, data=_data)


@dataclass(frozen=True)
class ScimApiLinkedAccount:
    issuer: str
    value: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls: type[ScimApiLinkedAccount], data: Mapping[str, Any]) -> ScimApiLinkedAccount:
        _issuer = data.get("issuer")
        if not isinstance(_issuer, str):
            raise ValueError("ScimApiLinkedAccount.issuer must be a string")
        _value = data.get("value")
        if not isinstance(_value, str):
            raise ValueError("ScimApiLinkedAccount.value must be a string")
        _parameters = data.get("parameters")
        if not isinstance(_parameters, dict):
            raise ValueError("ScimApiLinkedAccount.parameters must be a dict")
        return cls(issuer=_issuer, value=_value, parameters=_parameters)


@dataclass(frozen=True)
class ScimApiName:
    family_name: str | None = None
    given_name: str | None = None
    formatted: str | None = None
    middle_name: str | None = None
    honorific_prefix: str | None = None
    honorific_suffix: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)

    @classmethod
    def from_dict(cls: type[ScimApiName], data: Mapping[str, str | None]) -> ScimApiName:
        return cls(**data)


@dataclass(frozen=True)
class ScimApiEmail:
    value: str
    display: str | None = None
    type: EmailType | None = None
    primary: bool | None = None

    def to_dict(self) -> dict[str, str | None | bool]:
        res = asdict(self)
        if self.type is not None:
            res["type"] = self.type.value
        return res

    @classmethod
    def from_dict(cls: builtins.type[ScimApiEmail], data: Mapping[str, Any]) -> ScimApiEmail:
        email_type = None
        if data.get("type") is not None:
            email_type = EmailType(data["type"])
        return cls(value=data["value"], display=data.get("display"), type=email_type, primary=data.get("primary"))


@dataclass(frozen=True)
class ScimApiPhoneNumber:
    value: str
    display: str | None = None
    type: PhoneNumberType | None = None
    primary: bool | None = None

    def to_dict(self) -> dict[str, str | None | bool]:
        res = asdict(self)
        if self.type is not None:
            res["type"] = self.type.value
        return res

    @classmethod
    def from_dict(cls: builtins.type[ScimApiPhoneNumber], data: Mapping[str, Any]) -> ScimApiPhoneNumber:
        number_type = None
        if data.get("type") is not None:
            number_type = PhoneNumberType(data["type"])
        return cls(value=data["value"], display=data.get("display"), type=number_type, primary=data.get("primary"))
