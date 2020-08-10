# -*- coding: utf-8 -*-


from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from marshmallow import ValidationError, validates_schema
from marshmallow_dataclass import class_schema

from eduid_scimapi.schemas.scimbase import BaseSchema, DateTimeField, Email, Meta, Name, SCIMSchema, SCIMSchemaValue

__author__ = 'lundberg'


@dataclass(frozen=True)
class NutidExtensionV1:
    send_email: Optional[bool] = field(default=None, metadata={'data_key': 'sendEmail'})
    finish_url: Optional[str] = field(default=None, metadata={'data_key': 'finishURL'})
    invite_url: Optional[str] = field(default=None, metadata={'data_key': 'inviteURL'})
    completed: bool = False
    expires_at: Optional[datetime] = field(
        default=None, metadata={'data_key': 'expiresAt', 'marshmallow_field': DateTimeField()}
    )


@dataclass(frozen=True)
class InviteCreateRequest:
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    name: Name = field(default_factory=lambda: Name(), metadata={'required': True})
    emails: List[Email] = field(default_factory=list)
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_INVITE_V1.value, 'required': False},
    )

    @validates_schema
    def validate_schema(self, data, **kwargs):
        # Validate that at least one email address were provided if an invite email should be sent
        if data[SCIMSchema.NUTID_INVITE_V1.value]['send_email'] is True and len(data['emails']) == 0:
            raise ValidationError('There must be an email address to be able to send an invite mail.')


# TODO: Should we allow update?
# @dataclass(frozen=True)
# class InviteUpdateRequest:
#     id: UUID = field(metadata={'required': True})
#     schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
#     name: Name = field(default_factory=lambda: Name(), metadata={'required': True})
#     emails: List[Email] = field(default_factory=list)
#     nutid_v1: NutidExtensionV1 = field(
#         default_factory=lambda: NutidExtensionV1(),
#         metadata={'data_key': SCIMSchema.NUTID_INVITE_V1.value, 'required': False},
#     )


@dataclass(frozen=True)
class InviteResponse:
    id: UUID = field(metadata={'required': True})
    meta: Meta = field(metadata={'required': True})  # type: ignore
    external_id: Optional[str] = field(metadata={'data_key': 'externalId'}, default=None)
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    name: Name = field(default_factory=lambda: Name(), metadata={'required': True})
    emails: List[Email] = field(default_factory=list)
    nutid_v1: NutidExtensionV1 = field(
        default_factory=lambda: NutidExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_INVITE_V1.value, 'required': False},
    )


NutidInviteExtensionV1Schema = class_schema(NutidExtensionV1, base_schema=BaseSchema)
InviteCreateRequestSchema = class_schema(InviteCreateRequest, base_schema=BaseSchema)
# InviteUpdateRequestSchema = class_schema(UserUpdateRequest, base_schema=BaseSchema)
InviteResponseSchema = class_schema(InviteResponse, base_schema=BaseSchema)
