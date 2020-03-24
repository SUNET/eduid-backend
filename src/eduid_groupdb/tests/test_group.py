# -*- coding: utf-8 -*-
from typing import Dict, Union
from unittest import TestCase

from eduid_groupdb import Group, User

__author__ = 'lundberg'


class TestGroup(TestCase):
    def setUp(self) -> None:
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
            'description': 'Another test group',
        }
        self.user1: Dict[str, str] = {'identifier': 'user1', 'display_name': 'Test Testsson'}
        self.user2: Dict[str, str] = {'identifier': 'user2', 'display_name': 'Namn Namnsson'}

    def test_init_group(self):
        group = Group(**self.group1)
        self.assertEqual(self.group1['scope'], group.scope)
        self.assertEqual(self.group1['identifier'], group.identifier)
        self.assertEqual(self.group1['display_name'], group.display_name)
        self.assertEqual(self.group1['description'], group.description)

    def test_init_group_with_members(self):
        user = User(**self.user1)
        self.group1['members'] = [user]
        group = Group(**self.group1)
        self.assertIn(user, group.members)
        self.assertIn(user, group.user_members)
        self.assertEqual(0, len(group.group_members))
        group.members.append(Group(**self.group2))
        self.assertEqual(1, len(group.group_members))
        group.members.append(User(**self.user2))
        self.assertEqual(3, len(group.members))

    def test_init_group_with_owner_and_member(self):
        user = User(**self.user1)
        owner = User(**self.user2)
        self.group1['members'] = [user]
        self.group1['owners'] = [owner]
        group = Group(**self.group1)
        self.assertIn(user, group.members)
        self.assertIn(user, group.user_members)
        self.assertIn(owner, group.owners)
