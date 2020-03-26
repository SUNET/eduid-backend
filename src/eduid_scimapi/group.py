from dataclasses import dataclass, field
from typing import List
from uuid import UUID

from marshmallow_dataclass import class_schema

from eduid_scimapi.scimbase import BaseCreateRequest, BaseResponse, BaseUpdateRequest

__author__ = 'lundberg'


@dataclass
class GroupMember:
    value: UUID = field(metadata={'required': True})
    ref: str = field(metadata={'data_key': '$ref', 'required': True})
    display: str = field(metadata={'required': True})


@dataclass
class Group:
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})


@dataclass
class GroupCreateRequest(BaseCreateRequest, Group):
    pass


@dataclass
class GroupUpdateRequest(BaseUpdateRequest, Group):
    pass


@dataclass
class GroupResponse(BaseResponse, Group):
    pass


GroupCreateRequestSchema = class_schema(GroupCreateRequest)
GroupUpdateRequestSchema = class_schema(GroupUpdateRequest)
GroupResponseSchema = class_schema(GroupResponse)
