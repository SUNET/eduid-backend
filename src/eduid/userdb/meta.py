# -*- coding: utf-8 -*-

from datetime import datetime

from bson import ObjectId
from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now

__author__ = "lundberg"


class Meta(BaseModel):
    version: ObjectId = Field(default_factory=ObjectId)
    modified_ts: datetime = Field(default_factory=utc_now)

    class Config:
        arbitrary_types_allowed = True  # allow ObjectId as type
