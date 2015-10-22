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

from copy import deepcopy
from bson import ObjectId
from eduid_userdb.actions.db import ActionDB
from eduid_userdb.testing import MongoTestCase


USERID = '123467890123456789014567'
USERID2 = '123467890123456789014568'


DUMMY_ACTION = {
        '_id': ObjectId('234567890123456789012301'),
        'user_oid': ObjectId(USERID),
        'action': 'dummy',
        'preference': 200, 
        'params': {
            }
        }

TOU_ACTION = {
        '_id': ObjectId('234567890123456789012302'),
        'user_oid': ObjectId(USERID),  # same user_oid as DUMMY_ACTION
        'action': 'tou',
        'preference': 100,
        'params': {
            'version': 'test-version'
            }
        }

class TestActionsDB(MongoTestCase):

    def setUp(self):
        super(TestActionsDB, self).setUp(None, None)
        self.actionsdb = ActionDB(self.tmp_db.get_uri(''))
        self.actionsdb.add_action(data=TOU_ACTION)
        self.actionsdb.add_action(data=DUMMY_ACTION)

    def test_next_action(self):
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'dummy')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'tou')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action, None)

    def test_next_action_2_users(self):
        dummy_other_user = deepcopy(DUMMY_ACTION)
        dummy_other_user['user_oid'] = ObjectId(USERID2)
        del dummy_other_user['_id']
        self.actionsdb.add_action(data=dummy_other_user)
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'dummy')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'tou')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action, None)

    def test_next_action_2_users_add_by_keys(self):
        self.actionsdb.add_action(userid=USERID2,
                                  action_type='dummy',
                                  preference=300,
                                  session='zzz',
                                  params={})
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'dummy')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'tou')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action, None)

    def test_remove_action(self):
        self.actionsdb.remove_action_by_id(DUMMY_ACTION['_id'])
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'tou')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action, None)

    def test_next_action_with_no_session(self):
        dummy2 = deepcopy(DUMMY_ACTION)
        dummy2['session'] = 'xzf'
        del dummy2['_id']
        self.actionsdb.add_action(data=dummy2)
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'dummy')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'tou')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action, None)

    def test_next_action_with_session(self):
        dummy2 = deepcopy(DUMMY_ACTION)
        dummy2['session'] = 'xzf'
        del dummy2['_id']
        self.actionsdb.add_action(data=dummy2)
        next_action = self.actionsdb.get_next_action(USERID, session='xzf')
        self.assertEquals(next_action.action_type, 'dummy')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'dummy')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'tou')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action, None)

    def test_next_action_with_more_sessions(self):
        dummy2 = deepcopy(DUMMY_ACTION)
        dummy2['session'] = 'xzf'
        del dummy2['_id']
        self.actionsdb.add_action(data=dummy2)
        dummy3 = deepcopy(DUMMY_ACTION)
        dummy3['session'] = 'abc'
        del dummy3['_id']
        self.actionsdb.add_action(data=dummy3)
        next_action = self.actionsdb.get_next_action(USERID, session='xzf')
        self.assertEquals(next_action.action_type, 'dummy')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'dummy')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action.action_type, 'tou')
        next_action = self.actionsdb.get_next_action(USERID)
        self.assertEquals(next_action, None)

    def test_has_pending_actions(self):
        has = self.actionsdb.has_pending_actions(USERID)
        self.assertEquals(has, True)
        has = self.actionsdb.has_pending_actions(USERID2)
        self.assertEquals(has, False)

    def test_has_pending_actions_semi_consumed(self):
        first = self.actionsdb.get_next_action(USERID)
        has = self.actionsdb.has_pending_actions(USERID)
        self.assertEquals(has, True)

    def test_has_pending_actions_consumed(self):
        self.actionsdb.get_next_action(USERID)
        self.actionsdb.get_next_action(USERID)
        has = self.actionsdb.has_pending_actions(USERID)
        self.assertEquals(has, False)

    def test_has_actions(self):
        self.assertTrue(self.actionsdb.has_actions(userid=USERID))
        self.assertFalse(self.actionsdb.has_actions(userid=USERID2))
        self.assertTrue(self.actionsdb.has_actions(userid=USERID))
        self.assertFalse(self.actionsdb.has_actions(session='xzf'))
        dummy2 = deepcopy(DUMMY_ACTION)
        dummy2['session'] = 'xzf'
        del dummy2['_id']
        self.actionsdb.add_action(data=dummy2)
        self.assertTrue(self.actionsdb.has_actions(session='xzf'))
        self.assertTrue(self.actionsdb.has_actions(action_type='tou'))
        self.assertTrue(self.actionsdb.has_actions(params={'version': 'test-version'}))
        self.assertTrue(self.actionsdb.has_actions(userid=USERID,
                                                   action_type='tou',
                                                   params={'version': 'test-version'}))
