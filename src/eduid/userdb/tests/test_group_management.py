from uuid import uuid4

from pymongo.errors import DuplicateKeyError

from eduid.userdb.fixtures.users import UserFixtures
from eduid.userdb.group_management import GroupInviteState, GroupManagementInviteStateDB, GroupRole
from eduid.userdb.testing import MongoTestCase
from eduid.userdb.user import User

__author__ = "lundberg"


class TestResetGroupInviteStateDB(MongoTestCase):
    user: User

    def setUp(self):
        super().setUp()
        self.user = UserFixtures().mocked_user_standard
        self.invite_state_db = GroupManagementInviteStateDB(self.tmp_db.uri)

    def test_invite_state(self):
        # Member
        group_scim_id = str(uuid4())
        invite_state = GroupInviteState(
            group_scim_id=group_scim_id,
            email_address="johnsmith@example.com",
            role=GroupRole.MEMBER,
            inviter_eppn=self.user.eppn,
        )
        self.invite_state_db.save(invite_state, is_in_database=False)
        invite = self.invite_state_db.get_state(
            group_scim_id=group_scim_id, email_address="johnsmith@example.com", role=GroupRole.MEMBER
        )
        self.assertEqual(group_scim_id, invite.group_scim_id)
        self.assertEqual("johnsmith@example.com", invite.email_address)
        self.assertEqual(GroupRole.MEMBER, invite.role)

        # Owner
        group_scim_id = str(uuid4())
        invite_state = GroupInviteState(
            group_scim_id=group_scim_id,
            email_address="johnsmith@example.com",
            role=GroupRole.OWNER,
            inviter_eppn=self.user.eppn,
        )
        self.invite_state_db.save(invite_state, is_in_database=False)
        invite = self.invite_state_db.get_state(
            group_scim_id=group_scim_id, email_address="johnsmith@example.com", role=GroupRole.OWNER
        )
        self.assertEqual(group_scim_id, invite.group_scim_id)
        self.assertEqual("johnsmith@example.com", invite.email_address)
        self.assertEqual(GroupRole.OWNER, invite.role)

    def test_save_duplicate(self):
        group_scim_id = str(uuid4())
        invite_state1 = GroupInviteState(
            group_scim_id=group_scim_id,
            email_address="johnsmith@example.com",
            role=GroupRole.OWNER,
            inviter_eppn=self.user.eppn,
        )
        invite_state2 = GroupInviteState(
            group_scim_id=group_scim_id,
            email_address="johnsmith@example.com",
            role=GroupRole.OWNER,
            inviter_eppn=self.user.eppn,
        )

        self.invite_state_db.save(invite_state1, is_in_database=False)
        with self.assertRaises(DuplicateKeyError):
            self.invite_state_db.save(invite_state2, is_in_database=False)
