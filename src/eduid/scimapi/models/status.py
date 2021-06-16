# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from eduid.scimapi.models.scimbase import ModelConfig


class StatusResponse(ModelConfig):
    status: str
    hostname: str
    reason: str
