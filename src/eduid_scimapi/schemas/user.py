# from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional
from uuid import UUID

from marshmallow import fields
from marshmallow_dataclass import class_schema
from marshmallow_enum import EnumField

from eduid_scimapi.db.common import EventLevel
from eduid_scimapi.schemas.scimbase import (
    BaseCreateRequest,
    BaseResponse,
    BaseSchema,
    BaseUpdateRequest,
    Email,
    LanguageTagField,
    Name,
    PhoneNumber,
    SCIMSchema,
    SubResource,
)

__author__ = 'lundberg'


@dataclass(frozen=True)
class Profile:
    attributes: Dict[str, Any] = field(
        default_factory=dict, metadata={'marshmallow_field': fields.Dict(), 'required': False}
    )
    data: Dict[str, Any] = field(default_factory=dict, metadata={'marshmallow_field': fields.Dict(), 'required': False})


@dataclass(frozen=True)
class UserEvent:
    timestamp: datetime
    expires_at: datetime
    source: str
    data: Dict[str, Any]
    level: EventLevel = field(metadata={'marshmallow_field': EnumField(EventLevel, required=True, by_value=True)})
    id: UUID = fields.UUID(required=True)

    def to_dict(self) -> Dict[str, Any]:
        """ Return data in a format that the UserResponseSchema().dump() can handle """
        return asdict(self)

    @classmethod
    # def from_dict(cls: Type[UserEvent], data: Mapping[str, Any]) -> UserEvent:
    def from_dict(cls, data: Mapping[str, Any]):
        """
        Create a UserEvent from a dict.

        This dict can be the result from ScimApiEvent.to_dict(), where EventLevel is a string.
        """
        _data = dict(data)
        if isinstance(_data['level'], str):
            _data['level'] = EventLevel(_data['level'])
        return cls(**_data)


@dataclass(frozen=True)
class NutidUserExtensionV1:
    profiles: Dict[str, Profile] = field(
        default_factory=dict,
        metadata={
            'marshmallow_field': fields.Dict(keys=fields.Str, values=fields.Nested(class_schema(Profile))),
            'required': False,
        },
    )
    events: List[UserEvent] = field(
        default_factory=list,
        metadata={'marshmallow_field': fields.List(fields.Nested(class_schema(UserEvent))), 'required': False,},
    )


@dataclass(eq=True, frozen=True)
class Group(SubResource):
    pass


@dataclass(frozen=True)
class User:
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    name: Name = field(default_factory=lambda: Name(), metadata={'required': False})
    emails: List[Email] = field(default_factory=list)
    phone_numbers: List[PhoneNumber] = field(default_factory=list, metadata={'data_key': 'phoneNumbers'})
    preferred_language: Optional[str] = field(
        default=None, metadata={'marshmallow_field': LanguageTagField(data_key='preferredLanguage')}
    )
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    nutid_user_v1: NutidUserExtensionV1 = field(
        default_factory=lambda: NutidUserExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


@dataclass(frozen=True)
class UserCreateRequest(User, BaseCreateRequest):
    pass


@dataclass(frozen=True)
class UserUpdateRequest(User, BaseUpdateRequest):
    pass


@dataclass(frozen=True)
class UserResponse(User, BaseResponse):
    pass


NutidExtensionV1Schema = class_schema(NutidUserExtensionV1, base_schema=BaseSchema)
UserCreateRequestSchema = class_schema(UserCreateRequest, base_schema=BaseSchema)
UserUpdateRequestSchema = class_schema(UserUpdateRequest, base_schema=BaseSchema)
UserResponseSchema = class_schema(UserResponse, base_schema=BaseSchema)
