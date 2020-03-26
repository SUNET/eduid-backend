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
        self.group_db = GroupDB(db_uri=self.neo4jdb.db_uri, config=self.db_config)
        self.group1: Dict[str, Union[str, list, None]] = {
            'scope': 'example.com',
            'identifier': 'test1',
            'version': None,
            'display_name': 'Test Group 1',
            'description': 'A test group',
        }
        self.group2: Dict[str, Union[str, list, None]] = {
            'scope': 'another-example.com',
            'identifier': 'test2',
            'version': None,
            'display_name': 'Test Group 2',
            'description': 'Another test group',
        }
        self.user1: Dict[str, str] = {'identifier': 'user1', 'display_name': 'Test Testsson'}
        self.user2: Dict[str, str] = {'identifier': 'user2', 'display_name': 'Namn Namnsson'}

    def test_create_group(self):
        group = Group.from_mapping(self.group1)
        post_save_group = self.group_db.save(group)
        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(1, count)

        self.assertEqual(group.scope, post_save_group.scope)
        self.assertEqual(group.identifier, post_save_group.identifier)
        self.assertNotEqual(group.version, post_save_group.version)
        self.assertEqual(group.display_name, post_save_group.display_name)
        self.assertEqual(group.description, post_save_group.description)
        self.assertIsNotNone(post_save_group.created_ts)
        self.assertIsNone(post_save_group.modified_ts)

        get_group = self.group_db.get_group(scope='example.com', identifier='test1')
        self.assertEqual(group.scope, get_group.scope)
        self.assertEqual(group.identifier, get_group.identifier)
        self.assertEqual(post_save_group.version, get_group.version)
        self.assertEqual(group.display_name, get_group.display_name)
        self.assertEqual(group.description, get_group.description)
        self.assertIsNotNone(get_group.created_ts)

    def test_update_group(self):
        group = Group.from_mapping(self.group1)
        post_save_group = self.group_db.save(group)
        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(1, count)

        self.assertEqual(group.scope, post_save_group.scope)
        self.assertEqual(group.identifier, post_save_group.identifier)
        self.assertNotEqual(group.version, post_save_group.version)
        self.assertEqual(group.display_name, post_save_group.display_name)
        self.assertEqual(group.description, post_save_group.description)
        self.assertIsNotNone(post_save_group.created_ts)
        self.assertIsNone(post_save_group.modified_ts)

        group.display_name = 'A new display name'
        group.version = post_save_group.version
        post_save_group2 = self.group_db.save(group)
        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(1, count)

        self.assertEqual(group.scope, post_save_group2.scope)
        self.assertEqual(group.identifier, post_save_group2.identifier)
        self.assertNotEqual(group.version, post_save_group2.version)
        self.assertEqual(group.display_name, post_save_group2.display_name)
        self.assertEqual(group.description, post_save_group2.description)
        self.assertIsNotNone(post_save_group2.created_ts)
        self.assertIsNotNone(post_save_group2.modified_ts)

    def test_get_non_existing_group(self):
        group = self.group_db.get_group(scope='example.com', identifier='test1')
        self.assertIsNone(group)

    def test_group_exists(self):
        group = Group.from_mapping(self.group1)
        self.group_db.save(group)

        self.assertTrue(self.group_db.group_exists(scope=group.scope, identifier=group.identifier))
        self.assertFalse(self.group_db.group_exists(scope=group.scope, identifier='wrong-identifier'))
        self.assertFalse(self.group_db.group_exists(scope='wrong_scope', identifier=group.identifier))
        self.assertFalse(self.group_db.group_exists(scope='wrong_scope', identifier='wrong-identifier'))

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

        with self.group_db.db.driver.session() as session:
            group_count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
            user_count = session.run('MATCH (n:User) RETURN count(n) as c').single().value()
        self.assertEqual(1, group_count)
        self.assertEqual(1, user_count)

        post_save_group = self.group_db.get_group(scope='example.com', identifier='test1')
        post_save_user = post_save_group.member_users[0]
        self.assertEqual(user.identifier, post_save_user.identifier)
        self.assertEqual(user.display_name, post_save_user.display_name)

    def test_create_group_with_group_member(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)

        self.assertIn(member_group, group.member_groups)
        self.group_db.save(group)

        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(2, count)

        post_save_group = self.group_db.get_group(scope='example.com', identifier='test1')
        post_save_member_group = post_save_group.member_groups[0]
        self.assertEqual(member_group.scope, post_save_member_group.scope)
        self.assertEqual(member_group.identifier, post_save_member_group.identifier)
        self.assertEqual(member_group.display_name, post_save_member_group.display_name)
        self.assertEqual(member_group.description, post_save_member_group.description)

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

        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(2, count)

        post_save_group = self.group_db.get_group(scope='example.com', identifier='test1')
        post_save_member_group = post_save_group.member_groups[0]
        self.assertEqual(member_group.scope, post_save_member_group.scope)
        self.assertEqual(member_group.identifier, post_save_member_group.identifier)
        self.assertEqual(member_group.display_name, post_save_member_group.display_name)
        self.assertEqual(member_group.description, post_save_member_group.description)

        post_save_user = post_save_group.member_users[0]
        self.assertEqual(member_user.identifier, post_save_user.identifier)
        self.assertEqual(member_user.display_name, post_save_user.display_name)

        post_save_owner = post_save_group.owners[0]
        self.assertEqual(owner.identifier, post_save_owner.identifier)
        self.assertEqual(owner.display_name, post_save_owner.display_name)

    def test_get_groups_for_user(self):
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

        groups = self.group_db.get_groups_for_user(member_user)
        self.assertEqual(1, len(groups))
        self.assertEqual(group.scope, groups[0].scope)
        self.assertEqual(group.identifier, groups[0].identifier)
        self.assertEqual(group.display_name, groups[0].display_name)
        self.assertIsNotNone(groups[0].created_ts)

    def test_get_scoped_groups_for_user(self):
        group1 = Group.from_mapping(self.group1)
        group2 = Group.from_mapping(self.group2)
        member_user = User.from_mapping(self.user1)
        group1.members.append(member_user)
        group2.members.append(member_user)

        self.assertIn(member_user, group1.member_users)
        self.group_db.save(group1)
        self.assertIn(member_user, group2.member_users)
        self.group_db.save(group2)

        all_scope_groups = self.group_db.get_groups_for_user(member_user)
        self.assertEqual(2, len(all_scope_groups))

        groups = self.group_db.get_groups_for_user(member_user, scope='example.com')
        self.assertEqual(1, len(groups))
        self.assertEqual(group1.scope, groups[0].scope)
        self.assertEqual(group1.identifier, groups[0].identifier)
        self.assertEqual(group1.display_name, groups[0].display_name)
        self.assertIsNotNone(groups[0].created_ts)

    def test_remove_user_from_group(self):
        group = Group.from_mapping(self.group1)
        member_user1 = User.from_mapping(self.user1)
        member_user2 = User.from_mapping(self.user2)
        group.members.extend([member_user1, member_user2])

        self.assertIn(member_user1, group.member_users)
        self.assertIn(member_user2, group.member_users)
        post_save_group = self.group_db.save(group)

        self.assertIn(member_user1, post_save_group.member_users)
        self.assertIn(member_user2, post_save_group.member_users)

        group.members.remove(member_user1)
        self.assertNotIn(member_user1, group.member_users)
        self.assertIn(member_user2, group.member_users)
        group.version = post_save_group.version
        post_remove_group = self.group_db.save(group)

        self.assertNotIn(member_user1, post_remove_group.member_users)
        self.assertIn(member_user2, post_remove_group.member_users)

        get_group = self.group_db.get_group(scope='example.com', identifier='test1')
        self.assertNotIn(member_user1, get_group.member_users)
        self.assertIn(member_user2, get_group.member_users)
