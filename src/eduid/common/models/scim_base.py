from datetime import datetime
from enum import Enum
from typing import Annotated, Any
from uuid import UUID

from bson import ObjectId
from langcodes import standardize_tag
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    EmailStr,
    Field,
    PlainSerializer,
    WithJsonSchema,
)

from eduid.common.models.generic import ObjectIdPydanticAnnotation
from eduid.common.utils import make_etag, parse_weak_version, serialize_xml_datetime

__author__ = "lundberg"


# https://snipplr.com/view/11540/regex-for-tel-uris
PHONE_NUMBER_RFC_3966 = r"""^tel:((?:\+[\d().-]*\d[\d().-]*|[0-9A-F*#().-]*[0-9A-F*#][0-9A-F*#().-]*(?:
    ;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*;phone-context=(?:\+[\d().-]*\d[\d().-]*|
    (?:[a-z0-9]\.|[a-z0-9][a-z0-9-]*[a-z0-9]\.)*(?:[a-z]|[a-z][a-z0-9-]*[a-z0-9])))(?:;[a-z\d-]+(?:=
    (?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*(?:,(?:\+[\d().-]*\d[\d().-]*|[0-9A-F*#().-]*[0-9A-F*#]
    [0-9A-F*#().-]*(?:;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*;phone-context=\+[\d().-]*
    \d[\d().-]*)(?:;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*)*)$"""


WeakVersion = Annotated[
    ObjectId,
    ObjectIdPydanticAnnotation,
    BeforeValidator(parse_weak_version),
    PlainSerializer(make_etag, return_type=str),
    WithJsonSchema({"type": "str", "examples": ['W/"abc123"']}),
]

LowerEmailStr = Annotated[str, EmailStr, AfterValidator(lambda v: v.lower())]

PhoneNumberStr = Annotated[
    str,
    Field(pattern=PHONE_NUMBER_RFC_3966),
    WithJsonSchema({"type": "str", "description": "RFC 3966 phone number", "examples": ["tel:555-55555"]}),
]

LanguageTag = Annotated[
    str,
    BeforeValidator(lambda v: standardize_tag(v, macro=True)),
    WithJsonSchema({"type": "str", "description": "BCP 47 language tag", "examples": ["sv-se", "en-us"]}),
]


ScimDatetime = Annotated[datetime, PlainSerializer(serialize_xml_datetime)]


class SCIMSchema(str, Enum):
    CORE_20_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
    CORE_20_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
    API_MESSAGES_20_SEARCH_REQUEST = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
    API_MESSAGES_20_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
    NUTID_USER_V1 = "https://scim.eduid.se/schema/nutid/user/v1"
    NUTID_GROUP_V1 = "https://scim.eduid.se/schema/nutid/group/v1"
    NUTID_INVITE_CORE_V1 = "https://scim.eduid.se/schema/nutid/invite/core-v1"
    NUTID_INVITE_V1 = "https://scim.eduid.se/schema/nutid/invite/v1"
    NUTID_EVENT_CORE_V1 = "https://scim.eduid.se/schema/nutid/event/core-v1"
    NUTID_EVENT_V1 = "https://scim.eduid.se/schema/nutid/event/v1"
    DEBUG_V1 = "https://scim.eduid.se/schema/nutid-DEBUG/v1"


class SCIMResourceType(str, Enum):
    USER = "User"
    GROUP = "Group"
    INVITE = "Invite"
    EVENT = "Event"


class EmailType(str, Enum):
    HOME = "home"
    WORK = "work"
    OTHER = "other"


class PhoneNumberType(str, Enum):
    HOME = "home"
    WORK = "work"
    OTHER = "other"
    MOBILE = "mobile"
    FAX = "fax"
    PAGER = "pager"


class EduidBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class SubResource(EduidBaseModel):
    value: UUID
    ref: str = Field(alias="$ref")
    display: str

    @property
    def is_user(self):
        return self.ref and "/Users/" in self.ref

    @property
    def is_group(self):
        return self.ref and "/Groups/" in self.ref

    @classmethod
    def from_mapping(cls, data):
        return cls.model_validate(data)


class Meta(EduidBaseModel):
    location: str
    last_modified: ScimDatetime = Field(alias="lastModified")
    resource_type: SCIMResourceType = Field(alias="resourceType")
    created: ScimDatetime
    version: WeakVersion


class Name(EduidBaseModel):
    family_name: str | None = Field(default=None, alias="familyName")
    given_name: str | None = Field(default=None, alias="givenName")
    formatted: str | None = None
    middle_name: str | None = Field(default=None, alias="middleName")
    honorific_prefix: str | None = Field(default=None, alias="honorificPrefix")
    honorific_suffix: str | None = Field(default=None, alias="honorificSuffix")


class Email(EduidBaseModel):
    value: LowerEmailStr
    display: str | None = None
    type: EmailType | None = None
    primary: bool = True


class PhoneNumber(EduidBaseModel):
    value: PhoneNumberStr
    display: str | None = None
    type: PhoneNumberType | None = None
    primary: bool = True


class BaseResponse(EduidBaseModel):
    """This is basically the implementation of the common attributes defined in RFC7643 #3.1. (Common Attributes)"""

    id: UUID
    meta: Meta
    schemas: list[SCIMSchema] = Field(min_length=1)
    external_id: str | None = Field(default=None, alias="externalId")


class BaseCreateRequest(EduidBaseModel):
    schemas: list[SCIMSchema] = Field(min_length=1)
    external_id: str | None = Field(default=None, alias="externalId")


class BaseUpdateRequest(EduidBaseModel):
    id: UUID
    schemas: list[SCIMSchema] = Field(min_length=1)
    external_id: str | None = Field(default=None, alias="externalId")


class SearchRequest(EduidBaseModel):
    schemas: list[SCIMSchema] = Field(min_length=1, default=[SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST])
    filter: str
    start_index: int = Field(default=1, alias="startIndex", ge=1)  # Greater or equal to 1
    count: int = Field(default=100, ge=1)  # Greater or equal to 1
    attributes: list[str] | None = None


class ListResponse(EduidBaseModel):
    schemas: list[SCIMSchema] = Field(min_length=1, default=[SCIMSchema.API_MESSAGES_20_LIST_RESPONSE])
    resources: list[dict[Any, Any]] = Field(default_factory=list, alias="Resources")
    total_results: int = Field(default=0, alias="totalResults")
