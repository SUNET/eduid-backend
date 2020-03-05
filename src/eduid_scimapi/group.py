from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List
from uuid import UUID, uuid4

from bson import ObjectId
from bson.errors import InvalidId
from marshmallow import fields, ValidationError, missing
from marshmallow_enum import EnumField

from marshmallow_dataclass import NewType, class_schema

#from eduid_scimapi.profile import DEBUG_ALL_V1, NUTID_V1, Profile


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
    core_20_user = 'urn:ietf:params:scim:schemas:core:2.0:User'
    core_20_group = 'urn:ietf:params:scim:schemas:core:2.0:Group'


SCIMSchemaValue = NewType('SCIMSchemaValue', Enum, field=EnumField, enum=SCIMSchema, by_value=True)


class SCIMResourceType(Enum):
    user = 'User'
    group = 'Group'


@dataclass
class Meta:
    location: str = field(metadata={'required': True})
    last_modified: datetime = field(metadata={'data_key': 'lastModified', 'required': True})
    resource_type: SCIMResourceType = field(metadata={'data_key': 'resourceType', 'by_value': True, 'required': True})
    created: datetime = field(default_factory=datetime.utcnow, metadata={'required': True})
    version: ObjectId = field(default_factory=ObjectId,
                              metadata={'marshmallow_field': ObjectIdField(), 'required': True})


@dataclass
class Base:
    id: UUID = field(metadata={'required': True})
    meta: Meta = field(metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})


@dataclass
class GroupMember:
    id: UUID = field(metadata={'required': True})
    display_name: str = field(metadata={'data_key': 'displayName', 'required': True})


@dataclass
class Group(Base):
    display_name: str = field(default='', metadata={'data_key': 'displayName', 'required': True})
    members: List[GroupMember] = field(default_factory=list, metadata={'required': False})


s1 = class_schema(Meta)
meta = Meta(location='http://example.org/group/some-id', resource_type=SCIMResourceType.group,
            last_modified=datetime.utcnow(), version=ObjectId())
print(meta)
meta_dump = s1().dump(meta)
print(meta_dump)
print(s1().load(meta_dump))
print('------------------------------------------')

s2 = class_schema(Base)
base = Base(id=uuid4(), schemas=[SCIMSchema.core_20_group], meta=meta)
print(base)
base_dump = s2().dump(base)
print(base_dump)
print(s2().load(base_dump))
print('------------------------------------------')

s3 = class_schema(Group)
group = Group(id=uuid4(), schemas=[SCIMSchema.core_20_group], meta=meta, display_name='Test Group')
group.members.extend([GroupMember(id=uuid4(), display_name='Member 1'),
                      GroupMember(id=uuid4(), display_name='Member 2')])
print(group)
group_dump = s3().dump(group)
print(group_dump)
print(s3().load(group_dump))
