from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence
from uuid import UUID

from marshmallow import fields
from marshmallow_dataclass import class_schema

from eduid_scimapi.scimbase import BaseSchema, Meta, SCIMSchema, SCIMSchemaValue, SubResource

__author__ = 'lundberg'


@dataclass(frozen=True)
class NutidGroupExtensionV1:
    data: Dict[str, Any] = field(
        default_factory=dict, metadata={"marshmallow_field": fields.Dict(), 'required': False,},
    )


@dataclass(eq=True, frozen=True)
class GroupMember(SubResource):
    pass


@dataclass(frozen=True)
class Group:
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})
    nutid_group_v1: NutidGroupExtensionV1 = field(
        default_factory=lambda: NutidGroupExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_GROUP_V1.value, 'required': False},
    )


# Duplicate Group and BaseCreateRequest until dataclasses has better inheritance support
@dataclass(frozen=True)
class GroupCreateRequest:
    schemas: Sequence[SCIMSchemaValue] = field(
        default_factory=list, metadata={'marshmallow_field': fields.List(fields.Str()), 'required': True}
    )
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})
    nutid_group_v1: NutidGroupExtensionV1 = field(
        default_factory=lambda: NutidGroupExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_GROUP_V1.value, 'required': False},
    )


# Duplicate Group and BaseUpdateRequest until dataclasses has better inheritance support
@dataclass(frozen=True)
class GroupUpdateRequest:
    id: UUID = field(metadata={'required': True})
    schemas: Sequence[SCIMSchemaValue] = field(
        default_factory=list, metadata={'marshmallow_field': fields.List(fields.Str()), 'required': True}
    )
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})
    nutid_group_v1: NutidGroupExtensionV1 = field(
        default_factory=lambda: NutidGroupExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_GROUP_V1.value, 'required': False},
    )


# Duplicate Group and BaseResponse until dataclasses has better inheritance support
@dataclass(frozen=True)
class GroupResponse:
    id: UUID = field(metadata={'required': True})
    meta: Meta = field(metadata={'required': True})  # type: ignore
    schemas: Sequence[SCIMSchemaValue] = field(
        default_factory=list, metadata={'marshmallow_field': fields.List(fields.Str()), 'required': True}
    )
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})
    nutid_group_v1: NutidGroupExtensionV1 = field(
        default_factory=lambda: NutidGroupExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_GROUP_V1.value, 'required': False},
    )


GroupCreateRequestSchema = class_schema(GroupCreateRequest, base_schema=BaseSchema)
GroupUpdateRequestSchema = class_schema(GroupUpdateRequest, base_schema=BaseSchema)
GroupResponseSchema = class_schema(GroupResponse, base_schema=BaseSchema)
