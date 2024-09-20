from neo4j import basic_auth

from eduid.graphdb.db import BaseGraphDB
from eduid.graphdb.testing import Neo4jTestCase

__author__ = "lundberg"


class TestNeo4jDB(Neo4jTestCase):
    def test_create_db(self):
        with self.neo4jdb.driver.session() as session:
            session.run("CREATE (n:Test $props)", props={"name": "test node", "testing": True})
        with self.neo4jdb.driver.session() as session:
            result = session.run("MATCH (n {name: $name})RETURN n.testing", name="test node")
            self.assertTrue(result.single().value())


class TestBaseGraphDB(Neo4jTestCase):
    class TestDB(BaseGraphDB):
        def __init__(self, db_uri, config=None):
            super().__init__(db_uri, config=config)

        def db_setup(self):
            with self._db.driver.session() as session:
                session.run("CREATE CONSTRAINT ON (n:Test) ASSERT n.name IS UNIQUE")
                session.run("CREATE INDEX FOR (n:Test) ON (n.testing)")

    def test_base_db(self):
        db_uri = self.neo4jdb.db_uri

        config = {"encrypted": False, "auth": basic_auth("neo4j", "testingtesting")}
        test_db = self.TestDB(db_uri=db_uri, config=config)
        with test_db._db.driver.session() as session:
            session.run("CREATE (n:Test $props)", props={"name": "test node", "testing": True})
        with test_db._db.driver.session() as session:
            result = session.run("MATCH (n {name: $name})RETURN n.testing", name="test node")
            self.assertTrue(result.single().value())
