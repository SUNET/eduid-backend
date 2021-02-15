# -*- coding: utf-8 -*-

from __future__ import annotations

import typing
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Type, Union
from uuid import UUID

from eduid_scimapi.schemas.scimbase import EmailType, PhoneNumberType

__author__ = 'lundberg'

if typing.TYPE_CHECKING:
    from eduid_scimapi.schemas.user import UserEvent


@dataclass(frozen=True)
class ScimApiProfile:
    attributes: Dict[str, Any] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls: Type[ScimApiProfile], data: Mapping[str, Any]) -> ScimApiProfile:
        _attributes = data.get('attributes', {})
        _data = data.get('data', {})
        return cls(attributes=_attributes, data=_data)


@dataclass(frozen=True)
class ScimApiName:
    family_name: Optional[str] = None
    given_name: Optional[str] = None
    formatted: Optional[str] = None
    middle_name: Optional[str] = None
    honorific_prefix: Optional[str] = None
    honorific_suffix: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return asdict(self)

    @classmethod
    def from_dict(cls: Type[ScimApiName], data: Mapping[str, Optional[str]]) -> ScimApiName:
        return cls(**data)


@dataclass(frozen=True)
class ScimApiEmail:
    value: str
    display: Optional[str] = None
    type: Optional[EmailType] = None
    primary: Optional[bool] = None

    def to_dict(self) -> Dict[str, Union[Optional[str], bool]]:
        res = asdict(self)
        if self.type is not None:
            res['type'] = self.type.value
        return res

    @classmethod
    def from_dict(cls: Type[ScimApiEmail], data: Mapping[str, Any]) -> ScimApiEmail:
        email_type = None
        if data.get('type') is not None:
            email_type = EmailType(data['type'])
        return cls(value=data['value'], display=data.get('display'), type=email_type, primary=data.get('primary'))


@dataclass(frozen=True)
class ScimApiPhoneNumber:
    value: str
    display: Optional[str] = None
    type: Optional[PhoneNumberType] = None
    primary: Optional[bool] = None

    def to_dict(self) -> Dict[str, Union[Optional[str], bool]]:
        res = asdict(self)
        if self.type is not None:
            res['type'] = self.type.value
        return res

    @classmethod
    def from_dict(cls: Type[ScimApiPhoneNumber], data: Mapping[str, Any]) -> ScimApiPhoneNumber:
        number_type = None
        if data.get('type') is not None:
            number_type = PhoneNumberType(data['type'])
        return cls(value=data['value'], display=data.get('display'), type=number_type, primary=data.get('primary'))


@dataclass(frozen=True)
class ScimApiEvent:
    id: UUID
    timestamp: datetime
    expires_at: datetime
    source: str
    data: Dict[str, Any]
    level: EventLevel

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['id'] = str(self.id)
        data['level'] = self.level.value
        return data

    @classmethod
    def from_dict(cls: Type[ScimApiEvent], data: Mapping[str, Any]) -> ScimApiEvent:
        _data = dict(data)
        if not isinstance(_data['id'], UUID):
            _data['id'] = UUID(_data['id'])
        _data['level'] = EventLevel(_data['level'])
        return cls(**_data)


class EventLevel(Enum):
    DEBUG = 'debug'
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'
