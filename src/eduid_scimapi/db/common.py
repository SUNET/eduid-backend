# -*- coding: utf-8 -*-

from __future__ import annotations

import typing
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Type, Union
from uuid import UUID

from bson import ObjectId

from eduid_userdb.util import utc_now

from eduid_scimapi.schemas.scimbase import EmailType, PhoneNumberType

if typing.TYPE_CHECKING:
    from eduid_scimapi.schemas.user import UserEvent

__author__ = 'lundberg'


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


class EventLevel(Enum):
    DEBUG = 'debug'
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'


@dataclass(frozen=True)
class ScimApiEvent:
    scim_event_id: UUID
    scim_user_id: UUID
    level: EventLevel
    source: str
    data: Dict[str, Any]
    expires_at: datetime
    timestamp: datetime
    event_id: ObjectId = field(default_factory=lambda: ObjectId())  # mongodb document _id

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['_id'] = data.pop('event_id')
        data['scim_event_id'] = str(self.scim_event_id)
        data['scim_user_id'] = str(self.scim_user_id)
        data['level'] = self.level.value
        return data

    @classmethod
    def from_dict(cls: Type[ScimApiEvent], data: Mapping[str, Any]) -> ScimApiEvent:
        _data = dict(data)
        for _to_uuid in ['scim_event_id', 'scim_user_id']:
            _data[_to_uuid] = UUID(_data[_to_uuid])
        _data['level'] = EventLevel(_data['level'])
        if '_id' in _data:
            _data['event_id'] = _data.pop('_id')
        return cls(**_data)

    @classmethod
    def from_user_event(cls: Type[ScimApiEvent], user_event: 'UserEvent', scim_user_id: UUID) -> ScimApiEvent:
        return cls(
            data=user_event.data,
            expires_at=user_event.expires_at,
            level=user_event.level,
            scim_event_id=user_event.id,
            scim_user_id=scim_user_id,
            source=user_event.source,
            timestamp=utc_now(),
        )
