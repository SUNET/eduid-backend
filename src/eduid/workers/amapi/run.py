import os
from sys import stderr

from eduid.workers.amapi.app import init_api

__author__ = "masv"

DEBUG = os.environ.get("EDUID_APP_DEBUG", "False").lower() != "false"
if DEBUG:
    stderr.writelines("----- WARNING! EDUID_APP_DEBUG is enabled -----\n")

api = init_api()
