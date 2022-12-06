from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field
from common.misc.timeutil import utc_now

from eduid.userdb import MailAddress, PhoneNumber
from eduid.userdb.meta import CleanedType, Meta

__author__ = "masv"


class Reason(str, Enum):
    USER_DECEASED = "user_deceased"
    NAME_CHANGED = "name_changed"
    CAREGIVER_CHANGED = "caregiver_changed"
    READ_USER = "read_user"


class Source(str, Enum):
    SKV_NAVET_V2 = "swedish_tax_agency_navet_v2"
    NO_SOURCE = "no_source"


class UserBaseRequest(BaseModel):
    reason: str
    source: str


class UserUpdateResponse(BaseModel):
    status: bool
    diff: Optional[str] = None


class UserUpdateNameRequest(UserBaseRequest):
    given_name: Optional[str] = None
    display_name: Optional[str] = None
    surname: Optional[str] = None


class UserUpdateMetaRequest(UserBaseRequest):
    meta: Meta


class UserUpdateEmailRequest(UserBaseRequest):
    mail_addresses: List[MailAddress] = Field(default_factory=list)


class UserUpdatePhoneRequest(UserBaseRequest):
    phone_numbers: List[PhoneNumber] = Field(default_factory=list)


class UserUpdateLanguageRequest(UserBaseRequest):
    language: Optional[str] = None

class UserUpdateMetaCleanedRequest(UserBaseRequest):
    type: CleanedType
    ts: datetime = Field(default_factory=utc_now)

class UserUpdateTerminateRequest(UserBaseRequest):
    pass
