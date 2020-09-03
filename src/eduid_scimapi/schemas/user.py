from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import UUID

from marshmallow import fields
from marshmallow_dataclass import class_schema

from eduid_scimapi.schemas.scimbase import (
    BaseSchema,
    Email,
    LanguageTagField,
    Meta,
    Name,
    PhoneNumber,
    SCIMSchema,
    SCIMSchemaValue,
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
class NutidUserExtensionV1:
    profiles: Dict[str, Profile] = field(
        default_factory=dict,
        metadata={
            'marshmallow_field': fields.Dict(keys=fields.Str, values=fields.Nested(class_schema(Profile))),
            'required': False,
        },
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
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    preferred_language: Optional[str] = field(
        default=None, metadata={'data_key': 'preferredLanguage', 'marshmallow_field': LanguageTagField()}
    )
    nutid_user_v1: NutidUserExtensionV1 = field(
        default_factory=lambda: NutidUserExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


# Duplicate User and BaseCreateRequest until dataclasses has better inheritance support
@dataclass(frozen=True)
class UserCreateRequest:
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    name: Name = field(default_factory=lambda: Name(), metadata={'required': False})
    emails: List[Email] = field(default_factory=list)
    phone_numbers: List[PhoneNumber] = field(default_factory=list, metadata={'data_key': 'phoneNumbers'})
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    preferred_language: Optional[str] = field(
        default=None, metadata={'data_key': 'preferredLanguage', 'marshmallow_field': LanguageTagField()}
    )
    nutid_user_v1: NutidUserExtensionV1 = field(
        default_factory=lambda: NutidUserExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


# Duplicate User and BaseUpdateRequest until dataclasses has better inheritance support
@dataclass(frozen=True)
class UserUpdateRequest:
    id: UUID = field(metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    name: Name = field(default_factory=lambda: Name(), metadata={'required': False})
    emails: List[Email] = field(default_factory=list)
    phone_numbers: List[PhoneNumber] = field(default_factory=list, metadata={'data_key': 'phoneNumbers'})
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    preferred_language: Optional[str] = field(
        default=None, metadata={'data_key': 'preferredLanguage', 'marshmallow_field': LanguageTagField()}
    )
    nutid_user_v1: NutidUserExtensionV1 = field(
        default_factory=lambda: NutidUserExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


# Duplicate User and BaseResponse until dataclasses has better inheritance support
@dataclass(frozen=True)
class UserResponse:
    id: UUID = field(metadata={'required': True})
    meta: Meta = field(metadata={'required': True})  # type: ignore
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    name: Name = field(default_factory=lambda: Name(), metadata={'required': False})
    emails: List[Email] = field(default_factory=list)
    phone_numbers: List[PhoneNumber] = field(default_factory=list, metadata={'data_key': 'phoneNumbers'})
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    preferred_language: Optional[str] = field(
        default=None, metadata={'data_key': 'preferredLanguage', 'marshmallow_field': LanguageTagField()}
    )
    nutid_user_v1: NutidUserExtensionV1 = field(
        default_factory=lambda: NutidUserExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


NutidExtensionV1Schema = class_schema(NutidUserExtensionV1, base_schema=BaseSchema)
UserCreateRequestSchema = class_schema(UserCreateRequest, base_schema=BaseSchema)
UserUpdateRequestSchema = class_schema(UserUpdateRequest, base_schema=BaseSchema)
UserResponseSchema = class_schema(UserResponse, base_schema=BaseSchema)
