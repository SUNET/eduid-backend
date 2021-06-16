# -*- coding: utf-8 -*-

from eduid.scimapi.models.scimbase import ModelConfig

__author__ = 'lundberg'


class TokenRequest(ModelConfig):
    data_owner: str
