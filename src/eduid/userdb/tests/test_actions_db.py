#
# Copyright (c) 2015 NORDUnet A/S
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

import logging
from copy import deepcopy

from bson import ObjectId

from eduid.userdb.actions.db import ActionDB
from eduid.userdb.testing import MongoTestCase

logger = logging.getLogger(__name__)

USERID3 = "333333333333333333333333"
USERID4 = "444444444444444444444444"
EPPN3 = "hubba-bubba"
EPPN4 = "hussa-sussa"


DUMMY_ACTION = {
    "_id": ObjectId("111111111111111111111111"),
    "eppn": EPPN3,
    "action": "dummy",
    "preference": 200,
    "params": {},
}

TOU_ACTION = {
    "_id": ObjectId("222222222222222222222222"),
    "eppn": EPPN3,  # same eppn as DUMMY_ACTION
    "action": "tou",
    "preference": 100,
    "params": {"version": "test-version"},
}

DUMMY_ACTION_USERID = {
    "_id": ObjectId("111111111111111111111111"),
    "user_oid": ObjectId(USERID3),
    "action": "dummy",
    "preference": 200,
    "params": {},
}

TOU_ACTION_USERID = {
    "_id": ObjectId("222222222222222222222222"),
    "user_oid": ObjectId(USERID3),  # same user_oid as DUMMY_ACTION
    "action": "tou",
    "preference": 100,
    "params": {"version": "test-version"},
}


class TestActionsDB(MongoTestCase):
    def setUp(self):
        super().setUp()
        self.actionsdb = ActionDB(self.tmp_db.uri)
        self.actionsdb.add_action(data=TOU_ACTION)
        self.actionsdb.add_action(data=DUMMY_ACTION)

    def tearDown(self):
        self.actionsdb._drop_whole_collection()

    def test_remove_action(self):
        self.actionsdb.remove_action_by_id(DUMMY_ACTION["_id"])
        next_action = self.actionsdb.get_next_action(EPPN3)
        self.assertEqual(next_action.action_type, "tou")
        self.actionsdb.remove_action_by_id(next_action.action_id)
        next_action = self.actionsdb.get_next_action(EPPN3)
        self.assertEqual(next_action, None)

    def test_has_actions(self):
        self.assertTrue(self.actionsdb.has_actions(eppn_or_userid=EPPN3))
        self.assertFalse(self.actionsdb.has_actions(eppn_or_userid=EPPN4))
        self.assertTrue(self.actionsdb.has_actions(eppn_or_userid=EPPN3, session="xzf"))
        self.assertTrue(self.actionsdb.has_actions(eppn_or_userid=EPPN3, params={"version": "test-version"}))
        self.assertFalse(self.actionsdb.has_actions(eppn_or_userid=EPPN3, params={"version": "WRONG"}))
        self.assertTrue(
            self.actionsdb.has_actions(eppn_or_userid=EPPN3, action_type="tou", params={"version": "test-version"})
        )

    def test_update_action_with_result(self):
        action = self.actionsdb.get_next_action(EPPN3)
        action.result = {"test": True}
        self.actionsdb.update_action(action)
        # Saving a result on the action should make get_next_action advance to the next one
        next_action = self.actionsdb.get_next_action(EPPN3)
