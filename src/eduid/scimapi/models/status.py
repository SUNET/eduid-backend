# -*- coding: utf-8 -*-
__author__ = "lundberg"

from eduid.scimapi.models.scimbase import EduidBaseModel


class StatusResponse(EduidBaseModel):
    status: str
    hostname: str
    reason: str
