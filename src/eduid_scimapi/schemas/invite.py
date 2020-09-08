# -*- coding: utf-8 -*-
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from marshmallow import ValidationError, validate, validates_schema
from marshmallow_dataclass import class_schema

from eduid_scimapi.schemas.scimbase import (
    BaseCreateRequest,
    BaseResponse,
    BaseSchema,
    DateTimeField,
    Email,
    LanguageTagField,
    Meta,
    Name,
    PhoneNumber,
    SCIMSchema,
    SCIMSchemaValue,
)
from eduid_scimapi.schemas.user import NutidUserExtensionV1, UserCreateRequest, UserResponse

__author__ = 'lundberg'

# TODO: Copied from eduid-common, should probably be imported later
NIN_RE = re.compile(r'^(18|19|20)\d{2}(0[1-9]|1[0-2])\d{2}\d{4}$')


@dataclass(frozen=True)
class NutidInviteV1:
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    name: Name = field(default_factory=lambda: Name(), metadata={'required': False})
    emails: List[Email] = field(default_factory=list)
    phone_numbers: List[PhoneNumber] = field(default_factory=list, metadata={'data_key': 'phoneNumbers'})
    national_identity_number: Optional[str] = field(
        default=None,
        metadata={
            'data_key': 'nationalIdentityNumber',
            'required': False,
            'validate': validate.Regexp(NIN_RE, error='nin needs to be formatted as 18|19|20yymmddxxxx'),
        },
    )
    preferred_language: Optional[str] = field(
        default=None, metadata={'marshmallow_field': LanguageTagField(data_key='preferredLanguage')}
    )
    groups: List[UUID] = field(default_factory=list)
    inviter_name: Optional[str] = field(default=None, metadata={'data_key': 'inviterName', 'required': True})
    send_email: Optional[bool] = field(default=None, metadata={'data_key': 'sendEmail', 'required': True})
    finish_url: Optional[str] = field(default=None, metadata={'data_key': 'finishURL'})
    invite_url: Optional[str] = field(default=None, metadata={'data_key': 'inviteURL'})
    completed: Optional[datetime] = field(default=None, metadata={'marshmallow_field': DateTimeField()})
    expires_at: Optional[datetime] = field(
        default=None, metadata={'marshmallow_field': DateTimeField(data_key='expiresAt')}
    )
    nutid_user_v1: NutidUserExtensionV1 = field(
        default_factory=lambda: NutidUserExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


@dataclass(frozen=True)
class InviteCreateRequest(BaseCreateRequest, NutidInviteV1):
    pass

    @validates_schema
    def validate_schema(self, data, **kwargs):
        # Validate that at least one email address were provided if an invite email should be sent
        if data['send_email'] is True and len(data['emails']) == 0:
            raise ValidationError('There must be an email address to be able to send an invite mail.')
        # Validate that there is a primary email address if more than one is requested
        if len(data['emails']) > 1:
            primary_addresses = [email for email in data['emails'] if email.primary is True]
            if len(primary_addresses) == 0 or len(primary_addresses) > 1:
                raise ValidationError('There must be exactly one primary email address.')


@dataclass(frozen=True)
class InviteResponse(NutidInviteV1, BaseResponse):
    pass


NutidInviteV1Schema = class_schema(NutidInviteV1, base_schema=BaseSchema)
InviteCreateRequestSchema = class_schema(InviteCreateRequest, base_schema=BaseSchema)
# InviteUpdateRequestSchema = class_schema(UserUpdateRequest, base_schema=BaseSchema)
InviteResponseSchema = class_schema(InviteResponse, base_schema=BaseSchema)
