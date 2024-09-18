from typing import Any

from pydantic import Field

from eduid.common.models.scim_base import (
    BaseCreateRequest,
    BaseResponse,
    BaseUpdateRequest,
    EduidBaseModel,
    Email,
    LanguageTag,
    Name,
    PhoneNumber,
    SCIMSchema,
    SubResource,
)

__author__ = "lundberg"


class Profile(EduidBaseModel):
    attributes: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.dict()


class LinkedAccount(EduidBaseModel):
    issuer: str
    value: str
    parameters: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.dict()


class NutidUserExtensionV1(EduidBaseModel):
    profiles: dict[str, Profile] = Field(default_factory=dict)
    linked_accounts: list[LinkedAccount] = Field(default_factory=list)


class Group(SubResource):
    pass


class User(EduidBaseModel):
    name: Name = Field(default_factory=Name)
    emails: list[Email] = Field(default_factory=list)
    phone_numbers: list[PhoneNumber] = Field(default_factory=list, alias="phoneNumbers")
    preferred_language: LanguageTag | None = Field(default=None, alias="preferredLanguage")
    groups: list[Group] = Field(default_factory=list)
    nutid_user_v1: NutidUserExtensionV1 | None = Field(
        default_factory=NutidUserExtensionV1, alias=SCIMSchema.NUTID_USER_V1.value
    )


class UserCreateRequest(User, BaseCreateRequest):
    pass


class UserUpdateRequest(User, BaseUpdateRequest):
    pass


class UserResponse(User, BaseResponse):
    pass
