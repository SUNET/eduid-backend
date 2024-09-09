from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from eduid.userdb.db.async_db import AsyncBaseDB, AsyncMongoDB
from eduid.userdb.testing import AsyncMongoTestCase


class TestAsyncMongoDB(IsolatedAsyncioTestCase):
    async def test_full_uri(self):
        # full specified uri
        uri = "mongodb://db.example.com:1111/testdb"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        conn = mdb.get_connection()
        database = mdb.get_database()
        assert database is not None
        self.assertIsNotNone(conn)
        self.assertEqual(mdb._db_uri, uri)
        self.assertEqual(mdb._database_name, "testdb")

    async def test_uri_without_path_component(self):
        uri = "mongodb://db.example.com:1111"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        database = mdb.get_database()
        assert database is not None
        self.assertEqual(mdb._db_uri, uri + "/testdb")
        self.assertEqual(mdb._database_name, "testdb")

    async def test_uri_without_port(self):
        uri = "mongodb://db.example.com/"
        mdb = AsyncMongoDB(uri)
        self.assertEqual(mdb._db_uri, uri)
        database = mdb.get_database("testdb")
        assert database is not None
        self.assertEqual(mdb.sanitized_uri, "mongodb://db.example.com/")

    async def test_uri_with_username_and_password(self):
        uri = "mongodb://john:s3cr3t@db.example.com:1111/testdb"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        conn = mdb.get_connection()
        self.assertIsNotNone(conn)
        database = mdb.get_database()
        assert database is not None
        self.assertEqual(mdb._db_uri, uri)
        self.assertEqual(mdb._database_name, "testdb")
        self.assertEqual(mdb.sanitized_uri, "mongodb://john:secret@db.example.com:1111/testdb")
        self.assertEqual(
            mdb.__repr__(), "<eduID AsyncMongoDB: mongodb://john:secret@db.example.com:1111/testdb testdb>"
        )

    async def test_uri_with_replicaset(self):
        uri = "mongodb://john:s3cr3t@db.example.com,db2.example.com:27017,db3.example.com:1234/?replicaSet=rs9"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        self.assertEqual(mdb.sanitized_uri, "mongodb://john:secret@db.example.com/testdb?replicaset=rs9")
        self.assertEqual(
            mdb._db_uri,
            "mongodb://john:s3cr3t@db.example.com,db2.example.com,db3.example.com:1234/testdb?replicaset=rs9",
        )

    async def test_uri_with_options(self):
        uri = "mongodb://john:s3cr3t@db.example.com:27017/?ssl=true&replicaSet=rs9"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        self.assertEqual(mdb.sanitized_uri, "mongodb://john:secret@db.example.com/testdb?replicaset=rs9&tls=true")


class TestAsyncDB(AsyncMongoTestCase):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        # Make sure the isolated test cases get to create their own mongodb clients
        with patch("eduid.userdb.db.async_db.AsyncClientCache._clients", {}):
            self.db = AsyncBaseDB(db_uri=self.tmp_db.uri, db_name="testdb", collection="test")
        self.num_objs = 10
        await self.db.collection.insert_many([{"x": i} for i in range(self.num_objs)])

    async def test_db_count(self):
        self.assertEqual(self.num_objs, await self.db.db_count())

    async def test_db_count_limit(self):
        self.assertEqual(1, await self.db.db_count(limit=1))
        self.assertEqual(2, await self.db.db_count(limit=2))

    async def test_db_count_spec(self):
        self.assertEqual(1, await self.db.db_count(spec={"x": 3}))

    async def test_get_documents_by_filter_skip(self):
        docs = await self.db._get_documents_by_filter(spec={}, skip=2)
        self.assertEqual(8, len(docs))

    async def test_get_documents_by_filter_limit(self):
        docs = await self.db._get_documents_by_filter(spec={}, limit=1)
        self.assertEqual(1, len(docs))

    async def test_get_documents_by_aggregate(self):
        match = {
            "x": 3,
        }
        docs = await self.db._get_documents_by_aggregate(match=match)
        assert docs[0]["x"] == 3
