# -*- coding: utf-8 -*-

from datetime import datetime
from typing import Optional

from bson import ObjectId
from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now

__author__ = "lundberg"


class Meta(BaseModel):
    version: ObjectId = Field(default_factory=ObjectId)
    created_ts: datetime = Field(default_factory=utc_now)
    modified_ts: Optional[datetime]

    class Config:
        arbitrary_types_allowed = True  # allow ObjectId as type

    def new_version(self):
        self.version = ObjectId()
