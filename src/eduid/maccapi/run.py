import os
from sys import stderr

from eduid.maccapi.app import init_api

__author__ = "ylle"

DEBUG = os.environ.get("EDUID_APP_DEBUG", "False").lower() != "false"
if DEBUG:
    stderr.writelines("----- WARNING! EDUID_APP_DEBUG is enabled -----\n")

api = init_api()
