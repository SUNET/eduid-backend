# -*- coding: utf-8 -*-
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from marshmallow import ValidationError, validate, validates_schema
from marshmallow_dataclass import class_schema

from eduid_scimapi.schemas.scimbase import BaseSchema, DateTimeField, SCIMSchema
from eduid_scimapi.schemas.user import UserCreateRequest, UserResponse

__author__ = 'lundberg'

# TODO: Copied from eduid-common, should probably be imported later
NIN_RE = re.compile(r'^(18|19|20)\d{2}(0[1-9]|1[0-2])\d{2}\d{4}$')


@dataclass(frozen=True)
class NutidInviteExtensionV1:
    national_identity_number: Optional[str] = field(
        default=None,
        metadata={
            'data_key': 'nationalIdentityNumber',
            'required': False,
            'validate': validate.Regexp(NIN_RE, error='nin needs to be formatted as 18|19|20yymmddxxxx'),
        },
    )
    send_email: Optional[bool] = field(default=None, metadata={'data_key': 'sendEmail', 'required': True})
    finish_url: Optional[str] = field(default=None, metadata={'data_key': 'finishURL'})
    invite_url: Optional[str] = field(default=None, metadata={'data_key': 'inviteURL'})
    completed: Optional[datetime] = field(default=None, metadata={'marshmallow_field': DateTimeField()})
    expires_at: Optional[datetime] = field(
        default=None, metadata={'data_key': 'expiresAt', 'marshmallow_field': DateTimeField()}
    )


@dataclass(frozen=True)
class InviteCreateRequest(UserCreateRequest):
    nutid_invite_v1: NutidInviteExtensionV1 = field(
        default_factory=lambda: NutidInviteExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_INVITE_V1.value, 'required': False},
    )

    @validates_schema
    def validate_schema(self, data, **kwargs):
        # Validate that at least one email address were provided if an invite email should be sent
        if data[SCIMSchema.NUTID_INVITE_V1.value]['send_email'] is True and len(data['emails']) == 0:
            raise ValidationError('There must be an email address to be able to send an invite mail.')
        # Validate that there is a primary email address if more than one is requested
        if len(data['emails']) > 1:
            primary_addresses = [item for item in data['emails'] if item.get('primary') is True]
            if len(primary_addresses) == 0 or len(primary_addresses) > 1:
                raise ValidationError('There must be exactly one primary email address.')


# TODO: Should we allow update?
# @dataclass(frozen=True)
# class InviteUpdateRequest:
#     id: UUID = field(metadata={'required': True})
#     schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
#     name: Name = field(default_factory=lambda: Name(), metadata={'required': True})
#     emails: List[Email] = field(default_factory=list)
#     nutid_invite_v1: NutidExtensionV1 = field(
#         default_factory=lambda: NutidExtensionV1(),
#         metadata={'data_key': SCIMSchema.NUTID_INVITE_V1.value, 'required': False},
#     )


@dataclass(frozen=True)
class InviteResponse(UserResponse):
    nutid_invite_v1: NutidInviteExtensionV1 = field(
        default_factory=lambda: NutidInviteExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_INVITE_V1.value, 'required': False},
    )


NutidInviteExtensionV1Schema = class_schema(NutidInviteExtensionV1, base_schema=BaseSchema)
InviteCreateRequestSchema = class_schema(InviteCreateRequest, base_schema=BaseSchema)
# InviteUpdateRequestSchema = class_schema(UserUpdateRequest, base_schema=BaseSchema)
InviteResponseSchema = class_schema(InviteResponse, base_schema=BaseSchema)
