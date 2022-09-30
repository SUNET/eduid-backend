from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

from eduid.userdb import MailAddress, PhoneNumber

__author__ = "masv"

from eduid.userdb.meta import Meta


class Reason(str, Enum):
    USER_DECEASED = "user_deceased"
    NAME_CHANGED = "name_changed"
    CAREGIVER_CHANGED = "caregiver_changed"
    READ_USER = "read_user"


class Source(str, Enum):
    SKV_NAVET_V2 = "swedish_tax_agency_navet_v2"
    NO_SOURCE = "no_source"


class UserBaseRequest(BaseModel):
    reason: Optional[str] = None
    source: Optional[str] = None


class UserUpdateResponse(BaseModel):
    status: bool
    diff: str


class UserUpdateNameRequest(UserBaseRequest):
    given_name: Optional[str] = None
    display_name: Optional[str] = None
    surname: Optional[str] = None


class UserUpdateMetaRequest(UserBaseRequest):
    meta: Meta


class UserUpdateEmailRequest(UserBaseRequest):
    # mail_addresses: Optional[List[MailAddress]] = Field(default_factory=list)
    mail_addresses: List[MailAddress] = Field(default_factory=list)


class UserUpdatePhoneRequest(UserBaseRequest):
    phone_numbers: List[PhoneNumber] = Field(default_factory=list)


class UserUpdateLanguageRequest(UserBaseRequest):
    language: Optional[str] = None


class UserUpdateTerminateRequest(UserBaseRequest):
    pass