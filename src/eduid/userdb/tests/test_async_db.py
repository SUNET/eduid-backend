from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from eduid.userdb.db.async_db import AsyncBaseDB, AsyncMongoDB
from eduid.userdb.testing import AsyncMongoTestCase


class TestAsyncMongoDB(IsolatedAsyncioTestCase):
    def test_full_uri(self) -> None:
        # full specified uri
        uri = "mongodb://db.example.com:1111/testdb"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        conn = mdb.get_connection()
        database = mdb.get_database()
        assert database is not None
        assert conn is not None
        assert mdb._db_uri == uri
        assert mdb._database_name == "testdb"

    def test_uri_without_path_component(self) -> None:
        uri = "mongodb://db.example.com:1111"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        database = mdb.get_database()
        assert database is not None
        assert mdb._db_uri == uri + "/testdb"
        assert mdb._database_name == "testdb"

    def test_uri_without_port(self) -> None:
        uri = "mongodb://db.example.com/"
        mdb = AsyncMongoDB(uri)
        assert mdb._db_uri == uri
        database = mdb.get_database("testdb")
        assert database is not None
        assert mdb.sanitized_uri == "mongodb://db.example.com/"

    def test_uri_with_username_and_password(self) -> None:
        uri = "mongodb://john:s3cr3t@db.example.com:1111/testdb"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        conn = mdb.get_connection()
        assert conn is not None
        database = mdb.get_database()
        assert database is not None
        assert mdb._db_uri == uri
        assert mdb._database_name == "testdb"
        assert mdb.sanitized_uri == "mongodb://john:secret@db.example.com:1111/testdb"
        assert mdb.__repr__() == "<eduID AsyncMongoDB: mongodb://john:secret@db.example.com:1111/testdb testdb>"

    def test_uri_with_replicaset(self) -> None:
        uri = "mongodb://john:s3cr3t@db.example.com,db2.example.com:27017,db3.example.com:1234/?replicaSet=rs9"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        assert mdb.sanitized_uri == "mongodb://john:secret@db.example.com/testdb?replicaSet=rs9"
        assert mdb._db_uri == "mongodb://john:s3cr3t@db.example.com,db2.example.com,db3.example.com:1234/testdb?replicaSet=rs9"

    def test_uri_with_options(self) -> None:
        uri = "mongodb://john:s3cr3t@db.example.com:27017/?ssl=true&replicaSet=rs9"
        mdb = AsyncMongoDB(uri, db_name="testdb")
        assert mdb.sanitized_uri == "mongodb://john:secret@db.example.com/testdb?replicaSet=rs9&tls=true"


class TestAsyncDB(AsyncMongoTestCase):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        # Make sure the isolated test cases get to create their own mongodb clients
        with patch("eduid.userdb.db.async_db.AsyncClientCache._clients", {}):
            self.db = AsyncBaseDB(db_uri=self.tmp_db.uri, db_name="testdb", collection="test")
        self.num_objs = 10
        await self.db.collection.insert_many([{"x": i} for i in range(self.num_objs)])

    async def test_db_count(self) -> None:
        assert self.num_objs == await self.db.db_count()

    async def test_db_count_limit(self) -> None:
        assert await self.db.db_count(limit=1) == 1
        assert await self.db.db_count(limit=2) == 2

    async def test_db_count_spec(self) -> None:
        assert await self.db.db_count(spec={"x": 3}) == 1

    async def test_get_documents_by_filter_skip(self) -> None:
        docs = await self.db._get_documents_by_filter(spec={}, skip=2)
        assert len(docs) == 8

    async def test_get_documents_by_filter_limit(self) -> None:
        docs = await self.db._get_documents_by_filter(spec={}, limit=1)
        assert len(docs) == 1

    async def test_get_documents_by_aggregate(self) -> None:
        match = {
            "x": 3,
        }
        docs = await self.db._get_documents_by_aggregate(match=match)
        assert docs[0]["x"] == 3

    async def test_iter_documents_by_aggregate(self) -> None:
        match = {
            "x": 3,
        }
        docs = [doc async for doc in self.db._iter_documents_by_aggregate(match=match)]
        assert len(docs) == 1
        assert docs[0]["x"] == 3

    async def test_iter_documents_by_aggregate_no_match(self) -> None:
        match = {
            "x": 999,
        }
        docs = [doc async for doc in self.db._iter_documents_by_aggregate(match=match)]
        assert len(docs) == 0

    async def test_iter_documents_by_aggregate_with_projection(self) -> None:
        match = {
            "x": 3,
        }
        projection = {"x": 1, "_id": 0}
        docs = [doc async for doc in self.db._iter_documents_by_aggregate(match=match, projection=projection)]
        assert len(docs) == 1
        assert docs[0]["x"] == 3
        assert "_id" not in docs[0]

    async def test_iter_documents_by_aggregate_with_limit(self) -> None:
        match: dict[str, object] = {}
        docs = [doc async for doc in self.db._iter_documents_by_aggregate(match=match, limit=3)]
        assert len(docs) == 3

    async def test_iter_documents_by_aggregate_with_sort(self) -> None:
        match: dict[str, object] = {}
        sort = {"x": -1}
        docs = [doc async for doc in self.db._iter_documents_by_aggregate(match=match, sort=sort)]
        values = [doc["x"] for doc in docs]
        assert values == list(range(9, -1, -1))
