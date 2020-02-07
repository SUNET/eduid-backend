#
# Copyright (c) 2020 SUNET
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

from __future__ import absolute_import

import sys
import logging
import traceback
from contextlib import contextmanager
from copy import deepcopy
from typing import Optional, List, Dict, Any

from flask.testing import FlaskClient

from eduid_common.api.testing import APIMockedUserDB
from eduid_common.api.testing_base import CommonTestCase
from eduid_userdb import User
from eduid_userdb.db import BaseDB
from eduid_userdb.data_samples import (NEW_USER_EXAMPLE,
                                       NEW_UNVERIFIED_USER_EXAMPLE,
                                       NEW_COMPLETED_SIGNUP_USER_EXAMPLE)

logger = logging.getLogger(__name__)


NEW_U2F_USER_EXAMPLE = deepcopy(NEW_USER_EXAMPLE)
NEW_FIDO2_USER_EXAMPLE = deepcopy(NEW_USER_EXAMPLE)


_standard_test_users = {
    'hubba-bubba': NEW_USER_EXAMPLE,
    'hubba-baar': NEW_UNVERIFIED_USER_EXAMPLE,
    'hubba-fooo': NEW_COMPLETED_SIGNUP_USER_EXAMPLE,
    'hubba-fooo': NEW_U2F_USER_EXAMPLE,
    'hubba-fooo': NEW_FIDO2_USER_EXAMPLE,
}


class FidoTokensTestCase(CommonTestCase):
    """
    Test case for basic fido tokens operations.
    """
    # This concept with a class variable is broken - doesn't provide isolation between tests.
    # Do what we can and initialise it empty here, and then fill it in __init__.
    MockedUserDB = APIMockedUserDB

    def setUp(self, users: List[str]):
        """
        set up tests
        """
        # test users
        self.MockedUserDB.test_users = {}
        for this in users:
            self.MockedUserDB.test_users[this] = _standard_test_users.get(this)

        self.user = None
        # Initialize some convenience variables on self based on the first user in `users'
        self.test_user_data = _standard_test_users.get(users[0])
        self.test_user = User(data=self.test_user_data)

        super(EduidAPITestCase, self).setUp(users=users)

