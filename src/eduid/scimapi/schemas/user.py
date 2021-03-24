from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from marshmallow import fields
from marshmallow_dataclass import class_schema

from eduid.scimapi.schemas.scimbase import (
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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LinkedAccount:
    issuer: str
    value: str
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class NutidUserExtensionV1:
    profiles: Dict[str, Profile] = field(
        default_factory=dict,
        metadata={
            'marshmallow_field': fields.Dict(keys=fields.Str, values=fields.Nested(class_schema(Profile))),
            'required': False,
        },
    )
    linked_accounts: List[LinkedAccount] = field(default_factory=list, metadata={'required': False})


@dataclass(eq=True, frozen=True)
class Group(SubResource):
    pass


@dataclass(frozen=True)
class User:
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
