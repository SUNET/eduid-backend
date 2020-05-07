from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import UUID

from marshmallow import fields
from marshmallow_dataclass import class_schema

from eduid_scimapi.groupdb import ScimApiGroup
from eduid_scimapi.scimbase import BaseSchema, Meta, SCIMSchema, SCIMSchemaValue, SubResource

__author__ = 'lundberg'


@dataclass
class Profile:
    attributes: Dict[str, Any] = field(
        default_factory=dict, metadata={"marshmallow_field": fields.Dict(), 'required': False}
    )
    data: Dict[str, Any] = field(default_factory=dict, metadata={"marshmallow_field": fields.Dict(), 'required': False})


@dataclass
class NutidExtensionV1:
    profiles: Dict[str, Profile] = field(
        default_factory=dict,
        metadata={
            "marshmallow_field": fields.Dict(keys=fields.Str, values=fields.Nested(class_schema(Profile))),
            'required': False,
        },
    )


@dataclass
class Group(SubResource):
    pass


@dataclass
class User:
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


# Duplicate User and BaseCreateRequest until dataclasses has better inheritance support
@dataclass
class UserCreateRequest:
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


# Duplicate User and BaseUpdateRequest until dataclasses has better inheritance support
@dataclass
class UserUpdateRequest:
    id: UUID = field(metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


# Duplicate User and BaseResponse until dataclasses has better inheritance support
@dataclass
class UserResponse:
    id: UUID = field(metadata={'required': True})
    meta: Meta = field(metadata={'required': True})  # type: ignore
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    groups: List[Group] = field(default_factory=list, metadata={'required': False})
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


NutidExtensionV1Schema = class_schema(NutidExtensionV1, base_schema=BaseSchema)
UserCreateRequestSchema = class_schema(UserCreateRequest, base_schema=BaseSchema)
UserUpdateRequestSchema = class_schema(UserUpdateRequest, base_schema=BaseSchema)
UserResponseSchema = class_schema(UserResponse, base_schema=BaseSchema)
