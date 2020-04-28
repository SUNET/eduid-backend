from dataclasses import dataclass, field
from typing import Any, Dict, List
from uuid import UUID

from marshmallow import fields
from marshmallow_dataclass import class_schema

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
    attributes: Dict[str, Any] = field(
        default_factory=dict, metadata={"marshmallow_field": fields.Dict(), 'required': False,},
    )


@dataclass
class GroupMember(SubResource):
    pass


@dataclass
class Group:
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(), metadata={'data_key': SCIMSchema.NUTID_V1.value, 'required': False}
    )


# Duplicate Group and BaseCreateRequest until dataclasses has better inheritance support
@dataclass
class GroupCreateRequest:
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(), metadata={'data_key': SCIMSchema.NUTID_V1.value, 'required': False}
    )


# Duplicate Group and BaseUpdateRequest until dataclasses has better inheritance support
@dataclass
class GroupUpdateRequest:
    id: UUID = field(metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(), metadata={'data_key': SCIMSchema.NUTID_V1.value, 'required': False}
    )


# Duplicate Group and BaseResponse until dataclasses has better inheritance support
@dataclass
class GroupResponse:
    id: UUID = field(metadata={'required': True})
    meta: Meta = field(metadata={'required': True})  # type: ignore
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(), metadata={'data_key': SCIMSchema.NUTID_V1.value, 'required': False}
    )


GroupCreateRequestSchema = class_schema(GroupCreateRequest, base_schema=BaseSchema)
GroupUpdateRequestSchema = class_schema(GroupUpdateRequest, base_schema=BaseSchema)
GroupResponseSchema = class_schema(GroupResponse, base_schema=BaseSchema)
