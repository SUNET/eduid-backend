# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from marshmallow import fields
from marshmallow_dataclass import NewType, class_schema
from marshmallow_enum import EnumField

from eduid.scimapi.db.eventdb import EventLevel
from eduid.scimapi.schemas.scimbase import (
    BaseCreateRequest,
    BaseResponse,
    BaseSchema,
    DateTimeField,
    SCIMResourceType,
    SCIMSchema,
)

__author__ = 'ft'


SCIMResourceTypeValue = NewType(
    'SCIMResourceTypeValue', SCIMResourceType, field=EnumField, enum=SCIMResourceType, by_value=True
)


@dataclass
class NutidEventResource:
    resource_type: SCIMResourceTypeValue = field(metadata={'data_key': 'resourceType', 'required': True})
    scim_id: UUID = field(metadata={'data_key': 'id', 'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})
    location: Optional[str] = field(default=None, metadata={'required': False})


@dataclass(frozen=True)
class NutidEventExtensionV1:
    """
    All of these will be present in Events resource responses, but only some of them are required
    when creating an event: user_id, (external_id), level, data
    """

    resource: NutidEventResource = field(metadata={'required': True})
    level: EventLevel = field(
        default=EventLevel.INFO, metadata={'marshmallow_field': EnumField(EventLevel, required=True, by_value=True)}
    )
    data: Dict[str, Any] = field(
        default_factory=dict,
        metadata={'marshmallow_field': fields.Dict(keys=fields.Str, values=fields.Raw), 'required': True,},
    )
    expires_at: Optional[datetime] = field(
        default=None, metadata={'marshmallow_field': DateTimeField(data_key='expiresAt'), 'required': False}
    )
    timestamp: Optional[datetime] = field(
        default=None, metadata={'marshmallow_field': DateTimeField(data_key='timestamp'), 'required': False}
    )
    source: Optional[str] = field(default=None, metadata={'data_key': 'source', 'required': False})


@dataclass(frozen=True)
class NutidEventV1:
    nutid_event_v1: NutidEventExtensionV1 = field(
        metadata={'data_key': SCIMSchema.NUTID_EVENT_V1.value, 'required': True},
    )


@dataclass(frozen=True)
class EventCreateRequest(BaseCreateRequest, NutidEventV1):
    pass


@dataclass(frozen=True)
class EventResponse(BaseResponse, NutidEventV1):
    pass


NutidEventV1Schema = class_schema(NutidEventV1, base_schema=BaseSchema)
EventCreateRequestSchema = class_schema(EventCreateRequest, base_schema=BaseSchema)
EventResponseSchema = class_schema(EventResponse, base_schema=BaseSchema)
