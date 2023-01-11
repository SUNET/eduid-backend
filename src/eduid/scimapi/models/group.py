from typing import Any, Dict, List, Optional

from pydantic import Field

from eduid.common.models.scim_base import (
    BaseCreateRequest,
    BaseResponse,
    BaseUpdateRequest,
    EduidBaseModel,
    SCIMSchema,
    SubResource,
)

__author__ = "lundberg"


class NutidGroupExtensionV1(EduidBaseModel):
    data: dict[str, Any] = Field(default_factory=dict)


class GroupMember(SubResource):
    pass


class Group(EduidBaseModel):
    display_name: str = Field(alias="displayName")
    members: list[GroupMember] = Field(default_factory=list)
    nutid_group_v1: Optional[NutidGroupExtensionV1] = Field(
        default_factory=NutidGroupExtensionV1, alias=SCIMSchema.NUTID_GROUP_V1.value
    )


class GroupCreateRequest(Group, BaseCreateRequest):
    pass


class GroupUpdateRequest(Group, BaseUpdateRequest):
    pass


class GroupResponse(Group, BaseResponse):
    pass
