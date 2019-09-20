#
# Copyright (c) 2019 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

"""
Code used in unit tests of various eduID applications.
"""

__author__ = 'leifj'

import atexit
import logging
import random
import subprocess
import time
import unittest
from copy import deepcopy
from datetime import date, timedelta

import pymongo
from bson import ObjectId

from eduid_common.api.testing_base import CommonTestCase
from eduid_userdb import UserDB, User
from eduid_userdb.dashboard.user import DashboardUser

logger = logging.getLogger(__name__)


class AMTestCase(CommonTestCase):
    """TestCase with an embedded Attribute Manager.
    """

    def setUp(self, am_settings=None):
        """
        Test case initialization.

        """
        super(AMTestCase, self).setUp(am_settings=am_settings)
        import eduid_am
        celery = eduid_am.init_app(self.am_settings.celery)
        import eduid_am.worker
        eduid_am.worker.worker_config = self.am_settings
        logger.debug('Initialized AM with config:\n{!r}'.format(self.am_settings))

        self.am = eduid_am.get_attribute_manager(celery)
