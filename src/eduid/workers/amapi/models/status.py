# -*- coding: utf-8 -*-
__author__ = 'masv'

from eduid.workers.amapi.models.base import EduidBaseModel


class StatusResponse(EduidBaseModel):
    status: str
    hostname: str
    reason: str
