# -*- coding: utf-8 -*-

from datetime import datetime
from enum import Enum
from typing import Annotated, Optional

from bson import ObjectId
from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now

__author__ = "lundberg"


class CleanerType(str, Enum):
    SKV = "skatteverket"
    TELE = "teleadress"
    LADOK = "ladok"


class Meta(BaseModel):
    version: Optional[ObjectId] = None
    created_ts: datetime = Field(default_factory=utc_now)
    modified_ts: Optional[datetime] = None
    cleaned: Optional[dict[CleanerType, datetime]] = None
    is_in_database: Annotated[bool, Field(exclude=True)] = False  # this is set to True when userdb loads the object

    class Config:
        arbitrary_types_allowed = True  # allow ObjectId as type

    def new_version(self):
        self.version = ObjectId()
