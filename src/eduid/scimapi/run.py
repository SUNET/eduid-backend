# -*- coding: utf-8 -*-
import os
from sys import stderr

from eduid.scimapi.app import init_api

__author__ = "lundberg"

DEBUG = os.environ.get("EDUID_APP_DEBUG", False)
if DEBUG:
    stderr.writelines("----- WARNING! EDUID_APP_DEBUG is enabled -----\n")

api = init_api()
