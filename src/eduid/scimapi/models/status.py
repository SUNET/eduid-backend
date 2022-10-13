# -*- coding: utf-8 -*-
__author__ = "lundberg"

from eduid.common.models.scim_base import EduidBaseModel


class StatusResponse(EduidBaseModel):
    status: str
    hostname: str
    reason: str
