import os
from sys import stderr

from eduid.workers.job_runner.app import init_app

DEBUG = os.environ.get("EDUID_APP_DEBUG", "False").lower() != "false"
if DEBUG:
    stderr.writelines("----- WARNING! EDUID_APP_DEBUG is enabled -----\n")

app = init_app()
