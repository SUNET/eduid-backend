from dataclasses import dataclass, field
from typing import Any, Dict, List

from marshmallow import fields
from marshmallow_dataclass import class_schema

from eduid_scimapi.schemas.scimbase import (
    BaseCreateRequest,
    BaseResponse,
    BaseSchema,
    BaseUpdateRequest,
    SCIMSchema,
    SubResource,
)

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


@dataclass(frozen=True)
class GroupCreateRequest(Group, BaseCreateRequest):
    pass


@dataclass(frozen=True)
class GroupUpdateRequest(Group, BaseUpdateRequest):
    pass


@dataclass(frozen=True)
class GroupResponse(Group, BaseResponse):
    pass


GroupCreateRequestSchema = class_schema(GroupCreateRequest, base_schema=BaseSchema)
GroupUpdateRequestSchema = class_schema(GroupUpdateRequest, base_schema=BaseSchema)
GroupResponseSchema = class_schema(GroupResponse, base_schema=BaseSchema)
