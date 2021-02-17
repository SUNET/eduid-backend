# -*- coding: utf-8 -*-
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, Mapping, Optional
from uuid import UUID

from marshmallow import ValidationError, fields, validates_schema
from marshmallow_dataclass import class_schema
from marshmallow_enum import EnumField

from eduid_scimapi.db.common import EventLevel, ScimApiEvent
from eduid_scimapi.schemas.scimbase import (
    BaseCreateRequest,
    BaseResponse,
    BaseSchema,
    SCIMSchema,
)
from eduid_scimapi.schemas.user import NutidUserExtensionV1

__author__ = 'ft'

@dataclass(frozen=True)
class NutidEventExtensionV1:
    data: Dict[str, Any]
    expires_at: Optional[datetime]
    data_owner: Optional[str]
    timestamp: Optional[datetime]
    level: EventLevel = field(metadata={'marshmallow_field': EnumField(EventLevel, required=True, by_value=True)})
    id: UUID = fields.UUID(required=True)


@dataclass(frozen=True)
class NutidEventV1:
    nutid_event_v1: NutidEventExtensionV1 = field(
        default_factory=lambda: NutidUserExtensionV1(),
        metadata={'data_key': SCIMSchema.NUTID_USER_V1.value, 'required': False},
    )


@dataclass(frozen=True)
class EventCreateRequest(BaseCreateRequest, NutidEventV1):
    pass

    @validates_schema
    def validate_schema(self, data, **kwargs):
        # Validate that at least one email address were provided if an invite email should be sent
        if data['send_email'] is True and len(data['emails']) == 0:
            raise ValidationError('There must be an email address to be able to send an invite mail.')
        # Validate that there is a primary email address if more than one is requested
        if len(data['emails']) > 1:
            primary_addresses = [email for email in data['emails'] if email.primary is True]
            if len(primary_addresses) != 1:
                raise ValidationError('There must be exactly one primary email address.')


@dataclass(frozen=True)
class EventResponse(NutidEventV1, BaseResponse):
    pass


NutidEventV1Schema = class_schema(NutidEventV1, base_schema=BaseSchema)
EventCreateRequestSchema = class_schema(EventCreateRequest, base_schema=BaseSchema)
EventResponseSchema = class_schema(EventResponse, base_schema=BaseSchema)


@dataclass(frozen=True)
class XXUserEvent:
    data: Dict[str, Any]
    expires_at: Optional[datetime]
    data_owner: Optional[str]
    timestamp: Optional[datetime]
    level: EventLevel = field(metadata={'marshmallow_field': EnumField(EventLevel, required=True, by_value=True)})
    id: UUID = fields.UUID(required=True)

    def to_dict(self) -> Dict[str, Any]:
        """ Return data in a format that the UserResponseSchema().dump() can handle """
        return asdict(self)

    @classmethod
    # def from_dict(cls: Type[UserEvent], data: Mapping[str, Any]) -> UserEvent:
    def from_dict(cls, data: Mapping[str, Any]):
        """ Create a UserEvent from a dict. """
        _data = dict(data)
        if isinstance(_data['level'], str):
            _data['level'] = EventLevel(_data['level'])
        return cls(**_data)

    @classmethod
    # def from_scim_api_event(cls: Type[UserEvent], event: ScimApiEvent) -> UserEvent:
    def from_scim_api_event(cls, event: ScimApiEvent):
        """ Create a UserEvent from a ScimApiEvent. """
        return cls(
            data=event.data,
            expires_at=event.expires_at,
            source=event.data_owner,
            timestamp=event.timestamp,
            level=event.level,
            id=event.scim_event_id,
        )
