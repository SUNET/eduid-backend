import re
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union
from uuid import UUID

from bson import ObjectId
from langcodes import standardize_tag
from pydantic import ConfigDict, BaseModel, EmailStr, Field

__author__ = "lundberg"

from eduid.common.utils import make_etag

# https://snipplr.com/view/11540/regex-for-tel-uris
PHONE_NUMBER_RFC_3966 = re.compile(
    r"""^tel:((?:\+[\d().-]*\d[\d().-]*|[0-9A-F*#().-]*[0-9A-F*#][0-9A-F*#().-]*(?:
    ;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*;phone-context=(?:\+[\d().-]*\d[\d().-]*|
    (?:[a-z0-9]\.|[a-z0-9][a-z0-9-]*[a-z0-9]\.)*(?:[a-z]|[a-z][a-z0-9-]*[a-z0-9])))(?:;[a-z\d-]+(?:=
    (?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*(?:,(?:\+[\d().-]*\d[\d().-]*|[0-9A-F*#().-]*[0-9A-F*#]
    [0-9A-F*#().-]*(?:;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*;phone-context=\+[\d().-]*
    \d[\d().-]*)(?:;[a-z\d-]+(?:=(?:[a-z\d\[\]/:&+$_!~*'().-]|%[\dA-F]{2})+)?)*)*)$""",
    re.VERBOSE,
)


class WeakVersion(ObjectId):
    """
    Weak because we can not promise "strong" versioning, see https://datatracker.ietf.org/doc/html/rfc7232#section-2.1
    """

    @classmethod
    # TODO[pydantic]: We couldn't refactor `__get_validators__`, please create the `__get_pydantic_core_schema__` manually.
    # Check https://docs.pydantic.dev/latest/migration/#defining-custom-types for more information.
    def __get_validators__(cls):
        # one or more validators may be yielded which will be called in the
        # order to validate the input, each validator will receive as an input
        # the value returned from the previous validator
        yield cls.validate

    @classmethod
    # TODO[pydantic]: We couldn't refactor `__modify_schema__`, please create the `__get_pydantic_json_schema__` manually.
    # Check https://docs.pydantic.dev/latest/migration/#defining-custom-types for more information.
    def __modify_schema__(cls, field_schema):
        # __modify_schema__ should mutate the dict it receives in place,
        # the returned value will be ignored
        # TODO: Better documentation
        field_schema.update(
            pattern='W/"{version}"',
            # some example postcodes
            examples=['W/"abc123"'],
        )

    @classmethod
    def validate(cls, value):
        if isinstance(value, str) and value.startswith('W/"'):
            value = value.lstrip('W/"').rstrip('"')
        return cls(value)

    def __repr__(self):
        return f"WeakVersion({super().__repr__()})"

    @classmethod
    def serialize(cls, value: ObjectId):
        if value is None:
            return None
        return make_etag(value)


class LowerEmailStr(EmailStr):
    @classmethod
    def validate(cls, value: Union[str]) -> str:
        return super().validate(value=value.lower())


class PhoneNumberStr(str):
    @classmethod
    # TODO[pydantic]: We couldn't refactor `__get_validators__`, please create the `__get_pydantic_core_schema__` manually.
    # Check https://docs.pydantic.dev/latest/migration/#defining-custom-types for more information.
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    # TODO[pydantic]: We couldn't refactor `__modify_schema__`, please create the `__get_pydantic_json_schema__` manually.
    # Check https://docs.pydantic.dev/latest/migration/#defining-custom-types for more information.
    def __modify_schema__(cls, field_schema):
        # TODO: Better documentation
        field_schema.update(
            examples=["tel:555-55555"],
        )

    @classmethod
    def validate(cls, value):
        if not isinstance(value, str):
            raise TypeError("string required")
        value = value.lower()
        m = PHONE_NUMBER_RFC_3966.fullmatch(value)
        if not m:
            raise ValueError("invalid phone number format, needs to conform to RFC 3966")
        return cls(value)

    def __repr__(self):
        return f"PhoneNumberStr({super().__repr__()})"


class LanguageTag(str):
    @classmethod
    # TODO[pydantic]: We couldn't refactor `__get_validators__`, please create the `__get_pydantic_core_schema__` manually.
    # Check https://docs.pydantic.dev/latest/migration/#defining-custom-types for more information.
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    # TODO[pydantic]: We couldn't refactor `__modify_schema__`, please create the `__get_pydantic_json_schema__` manually.
    # Check https://docs.pydantic.dev/latest/migration/#defining-custom-types for more information.
    def __modify_schema__(cls, field_schema):
        # TODO: Better documentation
        field_schema.update(
            examples=["sv-se", "en-us"],
        )

    @classmethod
    def validate(cls, value):
        if not isinstance(value, str):
            raise TypeError("string required")
        # TODO: Does not validate that the input is a correct language tag
        # Replaces overlong tags with their shortest version, and also formats them according to the
        # conventions of BCP 47.
        return cls(standardize_tag(value, macro=True))

    def __repr__(self):
        return f"LanguageTag({super().__repr__()})"


def serialize_datetime(value: datetime) -> str:
    """
    The attribute value MUST be encoded as a valid xsd:dateTime as specified in Section 3.3.7 of
    XML-Schema (https://www.w3.org/TR/xmlschema11-2/) and MUST include both a date and a time.

    Example of a valid string: '2021-02-19T08:23:42+00:00'. Seconds are allowed to have decimals,
        so this is also valid: '2021-02-19T08:23:42.123456+00:00'
    """
    # When we load a datetime from mongodb, it will have milliseconds and not microseconds
    # so in order to be consistent we truncate microseconds to milliseconds always.
    milliseconds = value.microsecond // 1000
    return datetime.isoformat(value.replace(microsecond=milliseconds * 1000))


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
    # TODO[pydantic]: The following keys were removed: `json_encoders`.
    # Check https://docs.pydantic.dev/dev-v2/migration/#changes-to-config for more information.
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True, json_encoders={WeakVersion: WeakVersion.serialize, datetime: serialize_datetime})


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
        return cls.parse_obj(data)


class Meta(EduidBaseModel):
    location: str
    last_modified: datetime = Field(alias="lastModified")
    resource_type: SCIMResourceType = Field(alias="resourceType")
    created: datetime
    version: WeakVersion


class Name(EduidBaseModel):
    family_name: Optional[str] = Field(default=None, alias="familyName")
    given_name: Optional[str] = Field(default=None, alias="givenName")
    formatted: Optional[str] = None
    middle_name: Optional[str] = Field(default=None, alias="middleName")
    honorific_prefix: Optional[str] = Field(default=None, alias="honorificPrefix")
    honorific_suffix: Optional[str] = Field(default=None, alias="honorificSuffix")


class Email(EduidBaseModel):
    value: LowerEmailStr
    display: Optional[str] = None
    type: Optional[EmailType] = None
    primary: bool = True


class PhoneNumber(EduidBaseModel):
    value: PhoneNumberStr
    display: Optional[str] = None
    type: Optional[PhoneNumberType] = None
    primary: bool = True


class BaseResponse(EduidBaseModel):
    """This is basically the implementation of the common attributes defined in RFC7643 #3.1. (Common Attributes)"""

    id: UUID
    meta: Meta
    schemas: list[SCIMSchema] = Field(min_length=1)
    external_id: Optional[str] = Field(default=None, alias="externalId")


class BaseCreateRequest(EduidBaseModel):
    schemas: list[SCIMSchema] = Field(min_length=1)
    external_id: Optional[str] = Field(default=None, alias="externalId")


class BaseUpdateRequest(EduidBaseModel):
    id: UUID
    schemas: list[SCIMSchema] = Field(min_length=1)
    external_id: Optional[str] = Field(default=None, alias="externalId")


class SearchRequest(EduidBaseModel):
    schemas: list[SCIMSchema] = Field(min_length=1, default=[SCIMSchema.API_MESSAGES_20_SEARCH_REQUEST])
    filter: str
    start_index: int = Field(default=1, alias="startIndex", ge=1)  # Greater or equal to 1
    count: int = Field(default=100, ge=1)  # Greater or equal to 1
    attributes: Optional[list[str]] = None


class ListResponse(EduidBaseModel):
    schemas: list[SCIMSchema] = Field(min_length=1, default=[SCIMSchema.API_MESSAGES_20_LIST_RESPONSE])
    resources: list[dict[Any, Any]] = Field(default_factory=list, alias="Resources")
    total_results: int = Field(default=0, alias="totalResults")
