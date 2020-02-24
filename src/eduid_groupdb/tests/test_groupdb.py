# -*- coding: utf-8 -*-
from neo4j import basic_auth
from eduid_groupdb.testing import Neo4jTestCase
from eduid_groupdb import GroupDB, Group, User, Role

__author__ = 'lundberg'


class TestGroupDB(Neo4jTestCase):

    def setUp(self) -> None:
        self.db_config = {
            'encrypted': False,
            'auth': basic_auth('neo4j', 'testing')
        }
        self.group_db = GroupDB(db_uri=self.neo4jdb.db_uri, config=self.db_config)

    def test_create_group(self):
        group = Group(scope='example.com', identifier='test1', display_name='Test Group 1',
                      description='A test group')
        self.group_db.save(group)
        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(1, count)

    def test_create_group_with_user_member(self):
        group = Group(scope='example.com', identifier='test1', display_name='Test Group 1',
                      description='A test group')
        user = User(identifier='user1', role=Role.MEMBER, display_name='Test Testsson')
        group.members.append(user)
        self.group_db.save(group)
        with self.group_db.db.driver.session() as session:
            count = session.run('MATCH (n:Group) RETURN count(n) as c').single().value()
        self.assertEqual(1, count)

        print(self.group_db.get_group(scope='example.com', identifier='test1'))

