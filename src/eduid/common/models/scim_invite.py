from uuid import UUID

from pydantic import Field, model_validator
from typing_extensions import Self

from eduid.common.models.scim_base import (
    BaseCreateRequest,
    BaseResponse,
    BaseUpdateRequest,
    EduidBaseModel,
    Email,
    LanguageTag,
    Name,
    PhoneNumber,
    ScimDatetime,
    SCIMSchema,
)
from eduid.common.models.scim_user import NutidUserExtensionV1
from eduid.webapp.common.api.validation import nin_re_str

__author__ = "lundberg"


class NutidInviteExtensionV1(EduidBaseModel):
    name: Name = Field(default_factory=Name)
    emails: list[Email] = Field(default_factory=list)
    phone_numbers: list[PhoneNumber] = Field(default_factory=list, alias="phoneNumbers")
    national_identity_number: str | None = Field(
        default=None,
        alias="nationalIdentityNumber",
        pattern=nin_re_str,
    )
    preferred_language: LanguageTag | None = Field(default=None, alias="preferredLanguage")
    groups: list[UUID] = Field(default_factory=list)
    inviter_name: str | None = Field(default=None, alias="inviterName")
    send_email: bool | None = Field(default=None, alias="sendEmail")
    finish_url: str | None = Field(default=None, alias="finishURL")
    invite_url: str | None = Field(default=None, alias="inviteURL")
    enable_mfa_stepup: bool | None = Field(default=None, alias="enableMfaStepup")
    completed: ScimDatetime | None = None
    expires_at: ScimDatetime | None = Field(default=None, alias="expiresAt")

    @model_validator(mode="after")
    def validate_schema(self) -> Self:
        # Validate that at least one email address were provided if an invitation email should be sent
        if self.send_email is True and len(self.emails) == 0:
            raise ValueError("There must be an email address to be able to send an invite mail.")
        # Validate that there is a primary email address if more than one is requested
        if len(self.emails) > 1:
            primary_addresses = [email for email in self.emails if email.primary is True]
            if len(primary_addresses) != 1:
                raise ValueError("There must be exactly one primary email address.")
        # Validate that inviter_name and send_email is not None
        if self.send_email is None:
            raise ValueError("Missing sendEmail")
        if self.inviter_name is None:
            raise ValueError("Missing inviterName")
        return self


class NutidInviteV1(EduidBaseModel):
    nutid_invite_v1: NutidInviteExtensionV1 = Field(
        default_factory=NutidInviteExtensionV1,
        alias=SCIMSchema.NUTID_INVITE_V1.value,
    )
    nutid_user_v1: NutidUserExtensionV1 = Field(
        default_factory=NutidUserExtensionV1, alias=SCIMSchema.NUTID_USER_V1.value
    )


class InviteCreateRequest(NutidInviteV1, BaseCreateRequest):
    pass


class InviteUpdateRequest(NutidInviteV1, BaseUpdateRequest):
    pass


class InviteResponse(NutidInviteV1, BaseResponse):
    pass
