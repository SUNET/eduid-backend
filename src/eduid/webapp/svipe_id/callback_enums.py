# -*- coding: utf-8 -*-

from enum import Enum, unique

__author__ = "lundberg"


@unique
class SvipeIDAction(str, Enum):
    verify_identity = "verify-identity-action"
