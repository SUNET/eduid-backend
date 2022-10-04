# -*- coding: utf-8 -*-

from eduid.scimapi.models.scimbase import EduidBaseModel

__author__ = "lundberg"


class TokenRequest(EduidBaseModel):
    data_owner: str
