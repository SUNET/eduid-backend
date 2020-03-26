# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List
from uuid import UUID, uuid4

from bson import ObjectId
from bson.errors import InvalidId
from marshmallow import ValidationError, fields, missing
from marshmallow_dataclass import NewType, class_schema
from marshmallow_enum import EnumField

__author__ = 'lundberg'


class ObjectIdField(fields.Field):
    def _deserialize(self, value, attr, data, **kwargs):
        try:
            return ObjectId(value)
        except InvalidId:
            raise ValidationError(f'invalid ObjectId: {value}')

    def _serialize(self, value, attr, obj, **kwargs):
        if value is None:
            return missing
        return str(value)


class SCIMSchema(Enum):
    CORE_20_USER = 'urn:ietf:params:scim:schemas:core:2.0:User'
    CORE_20_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group'
    NUTID_V1 = 'https://scim.eduid.se/schema/nutid/v1'
    DEBUG_ALL_V1 = 'https://scim.eduid.se/schema/debug-all-profiles/v1'


SCIMSchemaValue = NewType('SCIMSchemaValue', Enum, field=EnumField, enum=SCIMSchema, by_value=True)


class SCIMResourceType(Enum):
    user = 'User'
    group = 'Group'


@dataclass
class Meta:
    location: str = field(default='', metadata={'required': True})
    last_modified: datetime = field(default='', metadata={'data_key': 'lastModified', 'required': True})
    resource_type: SCIMResourceType = field(
        default='', metadata={'data_key': 'resourceType', 'by_value': True, 'required': True}
    )
    created: datetime = field(default='', metadata={'required': True})
    version: ObjectId = field(
        default_factory=ObjectId, metadata={'marshmallow_field': ObjectIdField(), 'required': True}
    )


@dataclass
class BaseResponse:
    id: UUID = field(default='', metadata={'required': True})
    meta: Meta = field(default='', metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})


@dataclass
class BaseCreateRequest:
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})


@dataclass
class BaseUpdateRequest:
    id: UUID = field(default='', metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
