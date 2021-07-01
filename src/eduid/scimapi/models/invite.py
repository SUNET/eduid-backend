# -*- coding: utf-8 -*-
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from pydantic import Field, root_validator

from eduid.scimapi.models.scimbase import (
    BaseCreateRequest,
    BaseResponse,
    EduidBaseModel,
    Email,
    LanguageTag,
    Name,
    PhoneNumber,
    SCIMSchema,
)
from eduid.scimapi.models.user import NutidUserExtensionV1
from eduid.webapp.common.api.validation import nin_re_str

__author__ = 'lundberg'


class NutidInviteExtensionV1(EduidBaseModel):
    name: Name = Field(default_factory=Name)
    emails: List[Email] = Field(default_factory=list)
    phone_numbers: List[PhoneNumber] = Field(default_factory=list, alias='phoneNumbers')
    national_identity_number: Optional[str] = Field(
        default=None, alias='nationalIdentityNumber', regex=nin_re_str,
    )
    preferred_language: Optional[LanguageTag] = Field(default=None, alias='preferredLanguage')
    groups: List[UUID] = Field(default_factory=list)
    inviter_name: Optional[str] = Field(default=None, alias='inviterName')
    send_email: Optional[bool] = Field(default=None, alias='sendEmail')
    finish_url: Optional[str] = Field(default=None, alias='finishURL')
    invite_url: Optional[str] = Field(default=None, alias='inviteURL')
    completed: Optional[datetime] = None
    expires_at: Optional[datetime] = Field(default=None, alias='expiresAt')


class NutidInviteV1(EduidBaseModel):
    nutid_invite_v1: NutidInviteExtensionV1 = Field(
        default_factory=NutidInviteExtensionV1, alias=SCIMSchema.NUTID_INVITE_V1.value,
    )
    nutid_user_v1: NutidUserExtensionV1 = Field(
        default_factory=NutidUserExtensionV1, alias=SCIMSchema.NUTID_USER_V1.value
    )


class InviteCreateRequest(BaseCreateRequest, NutidInviteV1):
    @root_validator
    def validate_schema(cls, values) -> Dict:
        # Validate that at least one email address were provided if an invite email should be sent
        if values['nutid_invite_v1'].send_email is True and len(values['nutid_invite_v1'].emails) == 0:
            raise ValueError('There must be an email address to be able to send an invite mail.')
        # Validate that there is a primary email address if more than one is requested
        if len(values['nutid_invite_v1'].emails) > 1:
            primary_addresses = [email for email in values['nutid_invite_v1'].emails if email.primary is True]
            if len(primary_addresses) != 1:
                raise ValueError('There must be exactly one primary email address.')
        # Validate that inviter_name and send_email is not None
        if values['nutid_invite_v1'].send_email is None:
            raise ValueError('Missing sendEmail')
        if values['nutid_invite_v1'].inviter_name is None:
            raise ValueError('Missing inviterName')
        return values


class InviteResponse(NutidInviteV1, BaseResponse):
    pass
