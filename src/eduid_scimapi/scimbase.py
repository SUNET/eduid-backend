# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List
from uuid import UUID, uuid4

from bson import ObjectId
from bson.errors import InvalidId
from marshmallow import ValidationError, fields, missing
from marshmallow_dataclass import NewType, class_schema
from marshmallow_enum import EnumField

__author__ = 'lundberg'


class ObjectIdField(fields.Field):
    def _deserialize(self, value: str, attr, data, **kwargs):
        try:
            return ObjectId(value)
        except InvalidId:
            raise ValidationError(f'invalid ObjectId: {value}')

    def _serialize(self, value: ObjectId, attr, obj, **kwargs):
        if value is None:
            return missing
        return str(value)


class VersionField(ObjectIdField):
    def _deserialize(self, value: str, attr, data, **kwargs):
        try:
            if value.startswith('W/"'):
                value = value.lstrip('W/"').rstrip('"')
            return ObjectId(value)
        except InvalidId:
            raise ValidationError(f'invalid version: {value}')

    def _serialize(self, value: ObjectId, attr, obj, **kwargs):
        if value is None:
            return missing
        return make_etag(value)


def make_etag(version: ObjectId):
    return f'W/"{version}"'


class SCIMSchema(Enum):
    CORE_20_USER = 'urn:ietf:params:scim:schemas:core:2.0:User'
    CORE_20_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group'
    API_MESSAGES_20_SEARCH_REQUEST = 'urn:ietf:params:scim:api:messages:2.0:SearchRequest'
    API_MESSAGES_20_LIST_RESPONSE = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
    NUTID_V1 = 'https://scim.eduid.se/schema/nutid/v1'
    DEBUG_V1 = 'https://scim.eduid.se/schema/nutid-DEBUG/v1'


SCIMSchemaValue = NewType('SCIMSchemaValue', Enum, field=EnumField, enum=SCIMSchema, by_value=True)


class SCIMResourceType(Enum):
    user = 'User'
    group = 'Group'


@dataclass
class Meta:
    location: str = field(metadata={'required': True})
    last_modified: datetime = field(metadata={'data_key': 'lastModified', 'required': True})
    resource_type: SCIMResourceType = field(metadata={'data_key': 'resourceType', 'by_value': True, 'required': True})
    created: datetime = field(metadata={'required': True})
    version: ObjectId = field(metadata={'marshmallow_field': VersionField(), 'required': True})


@dataclass
class BaseResponse:
    id: UUID = field(metadata={'required': True})
    meta: Meta = field(metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})


@dataclass
class BaseCreateRequest:
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})


@dataclass
class BaseUpdateRequest:
    id: UUID = field(metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})


@dataclass
class SearchRequest:
    schemas: List[SCIMSchemaValue] = field(
        default_factory=lambda: [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST], metadata={'required': True}
    )
    filter: str = field(default='', metadata={'required': True})
    start_index: int = field(default=1, metadata={'data_key': 'startIndex', 'required': False})
    count: int = field(default=100, metadata={'required': False})


@dataclass
class ListResponse:
    schemas: List[SCIMSchemaValue] = field(
        default_factory=lambda: [SCIMSchema.API_MESSAGES_20_LIST_RESPONSE], metadata={'required': True}
    )
    resources: List[Dict[Any, Any]] = field(default_factory=list, metadata={'data_key': 'Resources', 'required': True})
    total_results: int = field(default=0, metadata={'data_key': 'totalResults', 'required': True})


SearchRequestSchema = class_schema(SearchRequest)
ListResponseSchema = class_schema(ListResponse)
