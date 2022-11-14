# -*- coding: utf-8 -*-

from datetime import datetime
from enum import Enum
from typing import Mapping, Optional

from bson import ObjectId
from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now

__author__ = "lundberg"


class CleanerType(str, Enum):
    SKV = "skv"
    TELE = "tele"
    LADOK = "ladok"


class Meta(BaseModel):
    version: ObjectId = Field(default_factory=ObjectId)
    created_ts: datetime = Field(default_factory=utc_now)
    modified_ts: Optional[datetime]

    class Config:
        arbitrary_types_allowed = True  # allow ObjectId as type

    def new_version(self):
        self.version = ObjectId()
