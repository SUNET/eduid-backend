# -*- coding: utf-8 -*-
from typing import Dict, Union

from neo4j import basic_auth

from eduid_groupdb import GroupDB, Group, User
from eduid_groupdb.testing import Neo4jTestCase

__author__ = 'lundberg'


class TestGroupDB(Neo4jTestCase):

    def setUp(self) -> None:
        self.db_config = {
            'encrypted': False,
            'auth': basic_auth('neo4j', 'testing')
        }
        self.group_db = GroupDB(db_uri=self.neo4jdb.db_uri, config=self.db_config)
        self.group1: Dict[str, Union[str, list]] = {
            'scope': 'example.com',
            'identifier': 'test1',
            'display_name': 'Test Group 1',
            'description': 'A test group',
        }
        self.group2: Dict[str, Union[str, list]] = {
            'scope': 'another-example.com',
            'identifier': 'test2',
            'display_name': 'Test Group 2',
            'description': 'Another test group'
        }
        self.user1: Dict[str, str] = {
            'identifier': 'user1',
            'display_name': 'Test Testsson'
        }
        self.user2: Dict[str, str] = {
            'identifier': 'user2',
            'display_name': 'Namn Namnsson'
        }

    def test_create_group(self):
        group = Group.from_mapping(self.group1)
        self.group_db.save(group)
        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(1, count)

        post_save_group = self.group_db.get_group(scope='example.com', identifier='test1')
        self.assertEqual(group.scope, post_save_group.scope)
        self.assertEqual(group.identifier, post_save_group.identifier)
        self.assertEqual(group.display_name, post_save_group.display_name)
        self.assertEqual(group.description, post_save_group.description)
        self.assertIsNotNone(post_save_group.created_ts)

    def test_create_group_with_user_member(self):
        group = Group.from_mapping(self.group1)
        user = User.from_mapping(self.user1)
        group.members.append(user)

        self.assertIn(user, group.members)
        self.group_db.save(group)

        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(1, count)

        post_save_group = self.group_db.get_group(scope='example.com', identifier='test1')
        post_save_user = post_save_group.user_members[0]
        self.assertEqual(user.identifier, post_save_user.identifier)
        self.assertEqual(user.display_name, post_save_user.display_name)

    def test_create_group_with_group_member(self):
        group = Group.from_mapping(self.group1)
        member_group = Group.from_mapping(self.group2)
        group.members.append(member_group)

        self.assertIn(member_group, group.group_members)
        self.group_db.save(group)

        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(2, count)

        post_save_group = self.group_db.get_group(scope='example.com', identifier='test1')
        post_save_member_group = post_save_group.group_members[0]
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

        self.assertIn(member_group, group.group_members)
        self.assertIn(member_user, group.user_members)
        self.assertIn(owner, group.owners)
        self.group_db.save(group)

        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(2, count)

        post_save_group = self.group_db.get_group(scope='example.com', identifier='test1')
        post_save_member_group = post_save_group.group_members[0]
        self.assertEqual(member_group.scope, post_save_member_group.scope)
        self.assertEqual(member_group.identifier, post_save_member_group.identifier)
        self.assertEqual(member_group.display_name, post_save_member_group.display_name)
        self.assertEqual(member_group.description, post_save_member_group.description)

        post_save_user = post_save_group.user_members[0]
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

        self.assertIn(member_group, group.group_members)
        self.assertIn(member_user, group.user_members)
        self.assertIn(owner, group.owners)
        self.group_db.save(group)

        groups = self.group_db.get_groups_for_user(member_user)
        self.assertEqual(1, len(groups))
        self.assertEqual(group.scope, groups[0].scope)
        self.assertEqual(group.identifier, groups[0].identifier)
        self.assertEqual(group.display_name, groups[0].display_name)
        self.assertIsNotNone(groups[0].created_ts)
