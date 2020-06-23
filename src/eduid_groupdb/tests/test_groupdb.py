# -*- coding: utf-8 -*-
from typing import Dict, Union

from bson import ObjectId
from neo4j import basic_auth

from eduid_groupdb import Group, GroupDB, User
from eduid_groupdb.exceptions import VersionMismatch
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

    def test_create_group(self):
        group = Group.from_mapping(self.group1)
        post_save_group = self.group_db.save(group)
        self.assertEqual(1, self.group_db.db.count_nodes(label='Group'))

        self.assertEqual(group.identifier, post_save_group.identifier)
        self.assertNotEqual(group.version, post_save_group.version)
        self.assertEqual(group.display_name, post_save_group.display_name)
        self.assertIsNotNone(post_save_group.created_ts)
        self.assertIsNone(post_save_group.modified_ts)

        get_group = self.group_db.get_group(identifier='test1')
        self.assertEqual(group.identifier, get_group.identifier)
        self.assertEqual(post_save_group.version, get_group.version)
        self.assertEqual(group.display_name, get_group.display_name)
        self.assertIsNotNone(get_group.created_ts)

    def test_update_group(self):
        group = Group.from_mapping(self.group1)
        post_save_group = self.group_db.save(group)
        self.assertEqual(1, self.group_db.db.count_nodes(label='Group'))

        self.assertEqual(group.identifier, post_save_group.identifier)
        self.assertNotEqual(group.version, post_save_group.version)
        self.assertEqual(group.display_name, post_save_group.display_name)
        self.assertIsNotNone(post_save_group.created_ts)
        self.assertIsNone(post_save_group.modified_ts)

        group.display_name = 'A new display name'
        group.version = post_save_group.version
        post_save_group2 = self.group_db.save(group)
        self.assertEqual(1, self.group_db.db.count_nodes(label='Group'))

        self.assertEqual(group.identifier, post_save_group2.identifier)
        self.assertNotEqual(group.version, post_save_group2.version)
        self.assertEqual(group.display_name, post_save_group2.display_name)
        self.assertIsNotNone(post_save_group2.created_ts)
        self.assertIsNotNone(post_save_group2.modified_ts)

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
        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(1, count)

    def test_create_group_with_user_member(self):
        group = Group.from_mapping(self.group1)
        user = User.from_mapping(self.user1)
        group.members.append(user)

        self.assertIn(user, group.members)
        self.group_db.save(group)

        self.assertEqual(1, self.group_db.db.count_nodes(label='Group'))
        self.assertEqual(1, self.group_db.db.count_nodes(label='User'))

        post_save_group = self.group_db.get_group(identifier='test1')
        post_save_user = post_save_group.member_users[0]
        self.assertEqual(user.identifier, post_save_user.identifier)
        self.assertEqual(user.display_name, post_save_user.display_name)

    def test_create_group_with_group_member(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)

        self.assertIn(member_group, group.member_groups)
        self.group_db.save(group)

        self.assertEqual(2, self.group_db.db.count_nodes(label='Group'))

        post_save_group = self.group_db.get_group(identifier='test1')
        post_save_member_group = post_save_group.member_groups[0]
        self.assertEqual(member_group.identifier, post_save_member_group.identifier)
        self.assertEqual(member_group.display_name, post_save_member_group.display_name)

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

        self.assertEqual(2, self.group_db.db.count_nodes(label='Group'))

        post_save_group = self.group_db.get_group(identifier='test1')
        post_save_member_group = post_save_group.member_groups[0]
        self.assertEqual(member_group.identifier, post_save_member_group.identifier)
        self.assertEqual(member_group.display_name, post_save_member_group.display_name)

        post_save_user = post_save_group.member_users[0]
        self.assertEqual(member_user.identifier, post_save_user.identifier)
        self.assertEqual(member_user.display_name, post_save_user.display_name)

        post_save_owner = post_save_group.owners[0]
        self.assertEqual(owner.identifier, post_save_owner.identifier)
        self.assertEqual(owner.display_name, post_save_owner.display_name)

    def test_get_groups_for_user_member(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = User.from_mapping(self.user1)
        group.owners.append(owner)

        self.assertIn(member_group, group.member_groups)
        self.assertIn(member_user, group.member_users)
        self.assertEqual(2, len(group.members))
        self.assertIn(owner, group.owners)
        self.assertEqual(1, len(group.owners))
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_member(member_user)
        self.assertEqual(1, len(groups))
        self.assertEqual(group.identifier, groups[0].identifier)
        self.assertEqual(group.display_name, groups[0].display_name)
        self.assertIsNotNone(groups[0].created_ts)
        self.assertEqual(1, len(group.owners))
        self.assertEqual(group.owners[0].identifier, groups[0].owners[0].identifier)
        self.assertEqual(group.owners[0].display_name, groups[0].owners[0].display_name)
        self.assertIsNotNone(groups[0].owners[0].created_ts)

    def test_get_groups_for_user_member_2(self):
        group1 = Group.from_mapping(self.group1)
        group2 = Group.from_mapping(self.group2)
        member_user = User.from_mapping(self.user1)
        group1.members.append(member_user)
        group2.members.append(member_user)

        self.assertIn(member_user, group1.member_users)
        self.group_db.save(group1)
        self.assertIn(member_user, group2.member_users)
        self.group_db.save(group2)

        groups = self.group_db.get_groups_for_member(member_user)
        self.assertEqual(2, len(groups))
        self.assertEqual(sorted([group1.identifier, group2.identifier]), sorted([x.identifier for x in groups]))
        self.assertEqual(sorted([group1.display_name, group2.display_name]), sorted([x.display_name for x in groups]))
        self.assertIsNotNone(groups[0].created_ts)

    def test_get_groups_for_group_member(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = User.from_mapping(self.user1)
        group.owners.append(owner)

        self.assertIn(member_group, group.member_groups)
        self.assertIn(member_user, group.member_users)
        self.assertEqual(2, len(group.members))
        self.assertIn(owner, group.owners)
        self.assertEqual(1, len(group.owners))
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_member(member_group)
        self.assertEqual(1, len(groups))
        self.assertEqual(group.identifier, groups[0].identifier)
        self.assertEqual(group.display_name, groups[0].display_name)
        self.assertIsNotNone(groups[0].created_ts)
        self.assertEqual(1, len(group.owners))
        self.assertEqual(group.owners[0].identifier, groups[0].owners[0].identifier)
        self.assertEqual(group.owners[0].display_name, groups[0].owners[0].display_name)
        self.assertIsNotNone(groups[0].owners[0].created_ts)

    def test_get_groups_for_user_owner(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = User.from_mapping(self.user1)
        group.owners.append(owner)

        self.assertIn(member_group, group.member_groups)
        self.assertIn(member_user, group.member_users)
        self.assertEqual(2, len(group.members), 'len(group.members)')
        self.assertIn(owner, group.owners)
        self.assertEqual(1, len(group.owners), 'len(group.owners)')
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_owner(owner)
        self.assertEqual(1, len(groups), 'len(groups)')
        self.assertEqual(group.identifier, groups[0].identifier)
        self.assertEqual(group.display_name, groups[0].display_name)
        self.assertIsNotNone(groups[0].created_ts)
        self.assertEqual(1, len(groups[0].owners), 'len(groups[0].owners)')
        self.assertEqual(group.owners[0].identifier, groups[0].owners[0].identifier)
        self.assertEqual(group.owners[0].display_name, groups[0].owners[0].display_name)
        self.assertIsNotNone(groups[0].owners[0].created_ts)
        self.assertEqual(2, len(groups[0].members), 'len(groups[0].members)')

    def test_get_groups_for_user_owner_2(self):
        group1 = Group.from_mapping(self.group1)
        group2 = Group.from_mapping(self.group2)
        owner_user = User.from_mapping(self.user1)
        member_user = User.from_mapping(self.user2)
        group1.owners.append(owner_user)
        group2.owners.append(owner_user)
        group1.members.append(member_user)
        group2.members.append(member_user)

        self.assertIn(owner_user, group1.owner_users)
        self.group_db.save(group1)
        self.assertIn(owner_user, group2.owner_users)
        self.group_db.save(group2)

        groups = self.group_db.get_groups_for_owner(owner_user)
        self.assertEqual(2, len(groups), 'len(groups)')
        self.assertEqual(sorted([group1.identifier, group2.identifier]), sorted([x.identifier for x in groups]))
        self.assertEqual(sorted([group1.display_name, group2.display_name]), sorted([x.display_name for x in groups]))
        self.assertIsNotNone(groups[0].created_ts)
        self.assertEqual(1, len(groups[0].members), 'len(groups[0].members)')
        self.assertEqual(1, len(groups[1].members), 'len(groups[1].members)')

    def test_get_groups_for_group_owner(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)
        member_user = User.from_mapping(self.user2)
        group.members.append(member_user)
        owner = Group.from_mapping(self.group2)
        group.owners.append(owner)

        self.assertIn(member_group, group.member_groups)
        self.assertIn(member_user, group.member_users)
        self.assertEqual(2, len(group.members), 'len(group.members)')
        self.assertIn(owner, group.owners)
        self.assertEqual(1, len(group.owners), 'len(group.owners)')
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_owner(owner)
        self.assertEqual(1, len(groups), 'len(groups)')
        self.assertEqual(group.identifier, groups[0].identifier)
        self.assertEqual(group.display_name, groups[0].display_name)
        self.assertIsNotNone(groups[0].created_ts)
        self.assertEqual(1, len(groups[0].owners), 'len(groups[0].owners)')
        self.assertEqual(group.owners[0].identifier, groups[0].owners[0].identifier)
        self.assertEqual(group.owners[0].display_name, groups[0].owners[0].display_name)
        self.assertIsNotNone(groups[0].owners[0].created_ts)
        self.assertEqual(2, len(groups[0].members), 'len(groups[0].members)')

    def test_remove_user_from_group(self):
        group = Group.from_mapping(self.group1)
        member_user1 = User.from_mapping(self.user1)
        member_user2 = User.from_mapping(self.user2)
        group.members.extend([member_user1, member_user2])

        self.assertIn(member_user1, group.members)
        self.assertIn(member_user2, group.members)
        post_save_group = self.group_db.save(group)

        self.assertIn(member_user1, post_save_group.members)
        self.assertIn(member_user2, post_save_group.members)

        group.members.remove(member_user1)
        self.assertNotIn(member_user1, group.members)
        self.assertIn(member_user2, group.members)
        group.version = post_save_group.version
        post_remove_group = self.group_db.save(group)

        self.assertNotIn(member_user1, post_remove_group.members)
        self.assertIn(member_user2, post_remove_group.members)

        get_group = self.group_db.get_group(identifier='test1')
        self.assertNotIn(member_user1, get_group.members)
        self.assertIn(member_user2, get_group.members)

    def test_remove_group_from_group(self):
        group = Group.from_mapping(self.group1)
        member_user1 = User.from_mapping(self.user1)
        member_group1 = Group.from_mapping(self.group2)
        group.members.extend([member_user1, member_group1])

        self.assertIn(member_user1, group.members)
        self.assertIn(member_group1, group.members)
        post_save_group = self.group_db.save(group)

        self.assertIn(member_user1, post_save_group.members)
        self.assertIn(member_group1, post_save_group.members)

        group.members.remove(member_group1)
        self.assertNotIn(member_group1, group.members)
        self.assertIn(member_user1, group.members)
        group.version = post_save_group.version
        post_remove_group = self.group_db.save(group)

        self.assertNotIn(member_group1, post_remove_group.members)
        self.assertIn(member_user1, post_remove_group.members)

        get_group = self.group_db.get_group(identifier=group.identifier)
        self.assertNotIn(member_group1, get_group.members)
        self.assertIn(member_user1, get_group.members)
