# -*- coding: utf-8 -*-
from neo4j import basic_auth

from eduid_groupdb.testing import Neo4jTestCase
from eduid_groupdb.db import BaseGraphDB

__author__ = 'lundberg'


class TestNeo4jDB(Neo4jTestCase):

    def test_create_db(self):
        with self.neo4jdb.driver.session() as session:
            session.run('CREATE (n:Test $props)', props={'name': 'test node', 'testing': True})
        with self.neo4jdb.driver.session() as session:
            result = session.run('MATCH (n {name: $name})'
                                 'RETURN n.testing',
                                 name='test node')
            self.assertTrue(result.single().value())


class TestBaseGraphDB(Neo4jTestCase):

    class TestDB(BaseGraphDB):
        def __init__(self, db_uri, config=None):
            super().__init__(db_uri, config)

        def db_setup(self):
            with self._db.driver.session() as session:
                session.run('CREATE CONSTRAINT ON (n:Test) ASSERT n.name IS UNIQUE')
                session.run('CREATE INDEX FOR (n:Test) ON (n.testing)')

    def test_base_db(self):
        db_uri = self.neo4jdb.db_uri

        config = {'encrypted': False, 'auth': basic_auth('neo4j', 'testing')}
        test_db = self.TestDB(db_uri=db_uri, config=config)
        with test_db._db.driver.session() as session:
            session.run('CREATE (n:Test $props)', props={'name': 'test node', 'testing': True})
        with test_db._db.driver.session() as session:
            result = session.run('MATCH (n {name: $name})'
                                 'RETURN n.testing',
                                 name='test node')
            self.assertTrue(result.single().value())
