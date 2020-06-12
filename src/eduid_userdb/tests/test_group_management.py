# -*- coding: utf-8 -*-
from uuid import uuid4

from pymongo.errors import DuplicateKeyError

from eduid_userdb.group_management import GroupInviteState, GroupManagementInviteStateDB
from eduid_userdb.testing import MongoTestCase

__author__ = 'lundberg'


class TestResetGroupInviteStateDB(MongoTestCase):
    def setUp(self, **kwargs):
        super().setUp(None, None)
        self.invite_state_db = GroupManagementInviteStateDB(self.tmp_db.uri)

    def test_invite_state(self):
        # Member
        group_id = str(uuid4())
        invite_state = GroupInviteState(group_id=group_id, email_address='johnsmith@example.com', role='member')
        self.invite_state_db.save(invite_state)
        invite = self.invite_state_db.get_state(group_id=group_id, email_address='johnsmith@example.com', role='member')
        self.assertEqual(group_id, invite.group_id)
        self.assertEqual('johnsmith@example.com', invite.email_address)
        self.assertEqual('member', invite.role)

        # Owner
        group_id = str(uuid4())
        invite_state = GroupInviteState(group_id=group_id, email_address='johnsmith@example.com', role='owner')
        self.invite_state_db.save(invite_state)
        invite = self.invite_state_db.get_state(group_id=group_id, email_address='johnsmith@example.com', role='owner')
        self.assertEqual(group_id, invite.group_id)
        self.assertEqual('johnsmith@example.com', invite.email_address)
        self.assertEqual('owner', invite.role)

    def test_save_duplicate(self):
        group_id = str(uuid4())
        invite_state1 = GroupInviteState(group_id=group_id, email_address='johnsmith@example.com', role='owner')
        invite_state2 = GroupInviteState(group_id=group_id, email_address='johnsmith@example.com', role='owner')

        self.invite_state_db.save(invite_state1)
        with self.assertRaises(DuplicateKeyError):
            self.invite_state_db.save(invite_state2)
