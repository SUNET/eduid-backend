# -*- coding: utf-8 -*-
from typing import Dict, Union

from bson import ObjectId
from neo4j import basic_auth

from eduid_groupdb.exceptions import VersionMismatch
from eduid_groupdb.groupdb import Group, GroupDB, User
from eduid_groupdb.testing import Neo4jTestCase

__author__ = 'lundberg'


class TestGroupDB(Neo4jTestCase):
    def setUp(self) -> None:
        self.db_config = {'encrypted': False, 'auth': basic_auth('neo4j', 'testing')}
        self.group_db = GroupDB(db_uri=self.neo4jdb.db_uri, scope='__testing__', config=self.db_config)
        self.group1: Dict[str, Union[str, list, None]] = {
            'identifier': 'test1',
            'version': None,
            'display_name': 'Test Group 1',
        }
        self.group2: Dict[str, Union[str, list, None]] = {
            'identifier': 'test2',
            'version': None,
            'display_name': 'Test Group 2',
        }
        self.user1: Dict[str, str] = {'identifier': 'user1', 'display_name': 'Test Testsson'}
        self.user2: Dict[str, str] = {'identifier': 'user2', 'display_name': 'Namn Namnsson'}

    @staticmethod
    def _assert_group(expected: Group, testing: Group, modified=False):
        assert expected.identifier == testing.identifier
        assert expected.display_name == testing.display_name
        assert testing.created_ts is not None
        if modified:
            assert expected.version != testing.version
            assert testing.modified_ts is not None
        else:
            assert testing.modified_ts is None

    @staticmethod
    def _assert_user(expected: User, testing: User):
        assert expected.identifier == testing.identifier
        assert expected.display_name == testing.display_name

    def test_create_group(self):
        group = Group.from_mapping(self.group1)
        post_save_group = self.group_db.save(group)
        assert 1 == self.group_db.db.count_nodes(label='Group')
        self._assert_group(group, post_save_group)

        get_group = self.group_db.get_group(identifier='test1')
        self._assert_group(group, get_group)

    def test_update_group(self):
        group = Group.from_mapping(self.group1)
        post_save_group = self.group_db.save(group)
        assert 1 == self.group_db.db.count_nodes(label='Group')
        self._assert_group(group, post_save_group)

        group.display_name = 'A new display name'
        group.version = post_save_group.version
        post_save_group2 = self.group_db.save(group)
        assert 1 == self.group_db.db.count_nodes(label='Group')
        self._assert_group(group, post_save_group2, modified=True)

    def test_get_non_existing_group(self):
        group = self.group_db.get_group(identifier='test1')
        self.assertIsNone(group)

    def test_group_exists(self):
        group = Group.from_mapping(self.group1)
        self.group_db.save(group)

        self.assertTrue(self.group_db.group_exists(identifier=group.identifier))
        self.assertFalse(self.group_db.group_exists(identifier='wrong-identifier'))

    def test_save_with_wrong_group_version(self):
        group = Group.from_mapping(self.group1)
        self.group_db.save(group)
        group.display_name = 'Another display name'
        group.version = ObjectId()
        with self.assertRaises(VersionMismatch):
            self.group_db.save(group)
        assert 1 == self.group_db.db.count_nodes(label='Group')

    def test_create_group_with_user_member(self):
        group = Group.from_mapping(self.group1)
        user = User.from_mapping(self.user1)
        group.members.append(user)

        self.assertIn(user, group.members)
        self.group_db.save(group)
        assert 1 == self.group_db.db.count_nodes(label='Group')
        assert 1 == self.group_db.db.count_nodes(label='User')

        post_save_group = self.group_db.get_group(identifier='test1')
        post_save_user = post_save_group.member_users[0]
        self._assert_user(user, post_save_user)

    def test_create_group_with_group_member(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)

        self.assertIn(member_group, group.member_groups)
        self.group_db.save(group)
        assert 2 == self.group_db.db.count_nodes(label='Group')

        post_save_group = self.group_db.get_group(identifier='test1')
        post_save_member_group = post_save_group.member_groups[0]
        self._assert_group(member_group, post_save_member_group)

    def test_create_group_with_group_member_and_user_owner(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = User.from_mapping(self.user1)
        group.owners.append(owner)

        self.assertIn(member_group, group.member_groups)
        self.assertIn(member_user, group.member_users)
        self.assertIn(owner, group.owners)
        self.group_db.save(group)
        assert 2 == self.group_db.db.count_nodes(label='Group')

        post_save_group = self.group_db.get_group(identifier='test1')
        post_save_member_group = post_save_group.member_groups[0]
        self._assert_group(member_group, post_save_member_group)

        post_save_user = post_save_group.member_users[0]
        self._assert_user(member_user, post_save_user)

        post_save_owner = post_save_group.owners[0]
        self._assert_user(owner, post_save_owner)

    def test_get_groups_for_user_member(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = User.from_mapping(self.user1)
        group.owners.append(owner)

        assert member_group in group.member_groups
        assert member_user in group.member_users
        assert 2 == len(group.members)
        assert owner in group.owners
        assert 1 == len(group.owners)
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_user_member(member_user.identifier)
        assert 1 == len(groups)
        self._assert_group(group, groups[0])
        assert 1 == len(group.owners)
        self._assert_group(group.owners[0], groups[0].owners[0])

    def test_get_groups_for_user_member_2(self):
        group1 = Group.from_mapping(self.group1)
        group2 = Group.from_mapping(self.group2)
        member_user = User.from_mapping(self.user1)
        group1.members.append(member_user)
        group2.members.append(member_user)

        assert member_user in group1.member_users
        self.group_db.save(group1)
        assert member_user in group2.member_users
        self.group_db.save(group2)

        groups = self.group_db.get_groups_for_user_member(member_user.identifier)
        assert 2 == len(groups)
        assert sorted([group1.identifier, group2.identifier]) == sorted([x.identifier for x in groups])
        assert sorted([group1.display_name, group2.display_name]) == sorted([x.display_name for x in groups])
        assert groups[0].created_ts is not None

    def test_get_groups_for_group_member(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = User.from_mapping(self.user1)
        group.owners.append(owner)

        assert member_group in group.member_groups
        assert member_user in group.member_users
        assert 2 == len(group.members)
        assert owner in group.owners
        assert 1 == len(group.owners)
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_group_member(member_group.identifier)
        assert 1 == len(groups)
        self._assert_group(group, groups[0])
        assert 1 == len(group.owners)
        self._assert_user(group.owners[0], groups[0].owners[0])

    def test_get_groups_for_user_owner(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = User.from_mapping(self.user1)
        group.owners.append(owner)

        assert member_group in group.member_groups
        assert member_user in group.member_users
        assert 2 == len(group.members)
        assert owner in group.owners
        assert 1 == len(group.owners)
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_user_owner(owner.identifier)
        assert 1 == len(groups)
        self._assert_group(group, groups[0])
        assert 1 == len(groups[0].owners)
        self._assert_group(group.owners[0], groups[0].owners[0])
        assert 2 == len(groups[0].members)

    def test_get_groups_for_user_owner_2(self):
        group1 = Group.from_mapping(self.group1)
        group2 = Group.from_mapping(self.group2)
        owner_user = User.from_mapping(self.user1)
        member_user = User.from_mapping(self.user2)
        group1.owners.append(owner_user)
        group2.owners.append(owner_user)
        group1.members.append(member_user)
        group2.members.append(member_user)

        assert owner_user in group1.owner_users
        self.group_db.save(group1)
        assert owner_user in group2.owner_users
        self.group_db.save(group2)

        groups = self.group_db.get_groups_for_user_owner(owner_user.identifier)
        assert 2 == len(groups)
        assert sorted([group1.identifier, group2.identifier]) == sorted([x.identifier for x in groups])
        assert sorted([group1.display_name, group2.display_name]) == sorted([x.display_name for x in groups])
        assert groups[0].created_ts is not None
        assert 1 == len(groups[0].members)
        assert 1 == len(groups[1].members)

    def test_get_groups_for_group_owner(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = Group.from_mapping(self.group2)
        group.owners.append(owner)

        assert member_group in group.member_groups
        assert member_user in group.member_users
        assert 2 == len(group.members)
        assert owner in group.owners
        assert 1 == len(group.owners)
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_group_owner(owner.identifier)
        assert 1 == len(groups)
        self._assert_group(group, groups[0])
        assert 1 == len(groups[0].owners)
        self._assert_group(group.owners[0], groups[0].owners[0])
        assert 2 == len(groups[0].members)

    def test_remove_user_from_group(self):
        group = Group.from_mapping(self.group1)
        member_user1 = User.from_mapping(self.user1)
        member_user2 = User.from_mapping(self.user2)
        group.members.extend([member_user1, member_user2])

        assert member_user1 in group.members
        assert member_user2 in group.members
        post_save_group = self.group_db.save(group)

        assert member_user1 in post_save_group.members
        assert member_user2 in post_save_group.members

        group.members.remove(member_user1)
        assert member_user1 not in group.members
        assert member_user2 in group.members
        group.version = post_save_group.version
        post_remove_group = self.group_db.save(group)

        assert member_user1 not in post_remove_group.members
        assert member_user2 in post_remove_group.members

        get_group = self.group_db.get_group(identifier='test1')
        assert member_user1 not in get_group.members
        assert member_user2 in get_group.members

    def test_remove_group_from_group(self):
        group = Group.from_mapping(self.group1)
        member_user1 = User.from_mapping(self.user1)
        member_group1 = Group.from_mapping(self.group2)
        group.members.extend([member_user1, member_group1])

        self.assertIn(member_user1, group.members)
        self.assertIn(member_group1, group.members)
        post_save_group = self.group_db.save(group)

        assert member_user1 in post_save_group.members
        assert member_group1 in post_save_group.members

        group.members.remove(member_group1)
        assert member_group1 not in group.members
        assert member_user1 in group.members
        group.version = post_save_group.version
        post_remove_group = self.group_db.save(group)

        assert member_group1 not in post_remove_group.members
        assert member_user1 in post_remove_group.members

        get_group = self.group_db.get_group(identifier=group.identifier)
        assert member_group1 not in get_group.members
        assert member_user1 in get_group.members
