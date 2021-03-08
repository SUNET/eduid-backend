# -*- coding: utf-8 -*-
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from bson import ObjectId
from bson.errors import InvalidId
from dateutil.parser import ParserError, parse  # type: ignore
from langcodes import standardize_tag
from marshmallow import Schema, ValidationError, fields, missing, post_dump, pre_load, validate
from marshmallow_dataclass import NewType, class_schema
from marshmallow_enum import EnumField

from eduid_scimapi.utils import make_etag

__author__ = 'lundberg'

# https://snipplr.com/view/11540/regex-for-tel-uris
PHONE_NUMBER_RFC_3966 = re.compile(
    r'''^tel:((?:\+[\d().-]*\d[\d().-]*|[0-9A-F*#().-]*[0-9A-F*#][0-9A-F*#().-]*(?:
    ;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*;phone-context=(?:\+[\d().-]*\d[\d().-]*|
    (?:[a-z0-9]\.|[a-z0-9][a-z0-9-]*[a-z0-9]\.)*(?:[a-z]|[a-z][a-z0-9-]*[a-z0-9])))(?:;[a-z\d-]+(?:=
    (?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*(?:,(?:\+[\d().-]*\d[\d().-]*|[0-9A-F*#().-]*[0-9A-F*#]
    [0-9A-F*#().-]*(?:;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*;phone-context=\+[\d().-]*
    \d[\d().-]*)(?:;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*)*)$''',
    re.VERBOSE,
)


class BaseSchema(Schema):
    SKIP_VALUES = [None]

    @post_dump
    def remove_skip_values(self, data, **kwargs):
        return {key: value for key, value in data.items() if value not in self.SKIP_VALUES}


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


class DateTimeField(fields.Field):
    """
    The attribute value MUST be encoded as a valid xsd:dateTime as specified in Section 3.3.7 of
    XML-Schema (https://www.w3.org/TR/xmlschema11-2/) and MUST include both a date and a time.

    Example of a valid string: '2021-02-19T08:23:42+00:00'. Seconds are allowed to have decimals,
        so this is also valid: '2021-02-19T08:23:42.123456+00:00'
    """

    def _deserialize(self, value: str, attr, data, **kwargs):
        try:
            return parse(value)  # Be liberal in what you accept...
        except ParserError as e:
            raise ValidationError(f'{e}')

    def _serialize(self, value: datetime, attr, obj, **kwargs):
        if value is None:
            return missing
        # When we load a datetime from mongodb, it will have milliseconds and not microseconds
        # so in order to be consistent we truncate microseconds to milliseconds always.
        milliseconds = value.microsecond // 1000
        return datetime.isoformat(value.replace(microsecond=milliseconds * 1000))


class LanguageTagField(fields.Field):
    def _deserialize(self, value: str, attr, data, **kwargs):
        try:
            # TODO: Does not validate that the input is a correct language tag
            # Replaces overlong tags with their shortest version, and also formats them according to the
            # conventions of BCP 47.
            return standardize_tag(value, macro=True)
        except ValueError as e:
            raise ValidationError(f'{e}')

    def _serialize(self, value: str, attr, obj, **kwargs):
        if value is None:
            return missing
        return value


class SCIMSchema(Enum):
    CORE_20_USER = 'urn:ietf:params:scim:schemas:core:2.0:User'
    CORE_20_GROUP = 'urn:ietf:params:scim:schemas:core:2.0:Group'
    API_MESSAGES_20_SEARCH_REQUEST = 'urn:ietf:params:scim:api:messages:2.0:SearchRequest'
    API_MESSAGES_20_LIST_RESPONSE = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
    ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error'
    NUTID_USER_V1 = 'https://scim.eduid.se/schema/nutid/user/v1'
    NUTID_GROUP_V1 = 'https://scim.eduid.se/schema/nutid/group/v1'
    NUTID_INVITE_CORE_V1 = 'https://scim.eduid.se/schema/nutid/invite/core-v1'
    NUTID_INVITE_V1 = 'https://scim.eduid.se/schema/nutid/invite/v1'
    NUTID_EVENT_CORE_V1 = 'https://scim.eduid.se/schema/nutid/event/core-v1'
    NUTID_EVENT_V1 = 'https://scim.eduid.se/schema/nutid/event/v1'
    DEBUG_V1 = 'https://scim.eduid.se/schema/nutid-DEBUG/v1'


SCIMSchemaValue = NewType('SCIMSchemaValue', SCIMSchema, field=EnumField, enum=SCIMSchema, by_value=True)


class SCIMResourceType(Enum):
    USER = 'User'
    GROUP = 'Group'
    INVITE = 'Invite'
    EVENT = 'Event'


class EmailType(Enum):
    HOME = 'home'
    WORK = 'work'
    OTHER = 'other'


class PhoneNumberType(Enum):
    HOME = 'home'
    WORK = 'work'
    OTHER = 'other'
    MOBILE = 'mobile'
    FAX = 'fax'
    PAGER = 'pager'


@dataclass(eq=True, frozen=True)
class SubResource:
    value: UUID = field(metadata={'required': True})
    ref: str = field(metadata={'data_key': '$ref', 'required': True})
    display: str = field(metadata={'required': True})

    @property
    def is_user(self):
        return self.ref and '/Users/' in self.ref

    @property
    def is_group(self):
        return self.ref and '/Groups/' in self.ref

    @classmethod
    def from_mapping(cls, data):
        return cls(value=UUID(data['value']), ref=data['$ref'], display=data['display'])


@dataclass(frozen=True)
class Meta:
    location: str = field(metadata={'required': True})
    last_modified: datetime = field(
        metadata={'marshmallow_field': DateTimeField(data_key='lastModified'), 'required': True}
    )
    resource_type: SCIMResourceType = field(metadata={'data_key': 'resourceType', 'by_value': True, 'required': True})
    created: datetime = field(metadata={'required': True})
    version: ObjectId = field(metadata={'marshmallow_field': VersionField(), 'required': True})


@dataclass(frozen=True)
class Name:
    family_name: Optional[str] = field(default=None, metadata={'data_key': 'familyName'})
    given_name: Optional[str] = field(default=None, metadata={'data_key': 'givenName'})
    formatted: Optional[str] = None
    middle_name: Optional[str] = field(default=None, metadata={'data_key': 'middleName'})
    honorific_prefix: Optional[str] = field(default=None, metadata={'data_key': 'honorificPrefix'})
    honorific_suffix: Optional[str] = field(default=None, metadata={'data_key': 'honorificSuffix'})


@dataclass(frozen=True)
class Email:
    value: str = field(metadata={'required': True, 'validate': validate.Email()})
    display: Optional[str] = None
    type: Optional[EmailType] = field(metadata={'by_value': True}, default=None)
    primary: bool = True

    @pre_load
    def value_to_lower(self, data, **kwargs):
        data['value'] = data['value'].lower()
        return data


@dataclass(frozen=True)
class PhoneNumber:
    value: str = field(
        metadata={
            'required': True,
            'validate': validate.Regexp(
                PHONE_NUMBER_RFC_3966, error='Phone number format needs to conform to RFC 3966'
            ),
        }
    )
    display: Optional[str] = None
    type: Optional[PhoneNumberType] = field(metadata={'by_value': True}, default=None)
    primary: bool = True

    @pre_load
    def value_to_lower(self, data, **kwargs):
        data['value'] = data['value'].lower()
        return data


@dataclass(frozen=True)
class BaseResponse:
    """ This is basically the implementation of the common attributes defined in RFC7643 #3.1. (Common Attributes) """

    id: UUID = field(metadata={'required': True})
    meta: Meta = field(metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})


@dataclass(frozen=True)
class BaseCreateRequest:
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})


@dataclass(frozen=True)
class BaseUpdateRequest:
    id: UUID = field(metadata={'required': True})
    schemas: List[SCIMSchemaValue] = field(default_factory=list, metadata={'required': True})
    external_id: Optional[str] = field(default=None, metadata={'data_key': 'externalId', 'required': False})


@dataclass(frozen=True)
class SearchRequest:
    schemas: List[SCIMSchemaValue] = field(
        default_factory=lambda: [SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST], metadata={'required': True}
    )
    filter: str = field(default='', metadata={'required': True})
    start_index: int = field(
        default=1, metadata={'data_key': 'startIndex', 'required': False, 'validate': validate.Range(min=1)}
    )
    count: int = field(default=100, metadata={'required': False, 'validate': validate.Range(min=1)})


@dataclass(frozen=True)
class ListResponse:
    schemas: List[SCIMSchemaValue] = field(
        default_factory=lambda: [SCIMSchema.API_MESSAGES_20_LIST_RESPONSE], metadata={'required': True}
    )
    resources: List[Dict[Any, Any]] = field(default_factory=list, metadata={'data_key': 'Resources', 'required': True})
    total_results: int = field(default=0, metadata={'data_key': 'totalResults', 'required': True})


SearchRequestSchema = class_schema(SearchRequest, base_schema=BaseSchema)
ListResponseSchema = class_schema(ListResponse, base_schema=BaseSchema)
