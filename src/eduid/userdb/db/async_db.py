import logging
from collections.abc import Mapping
from typing import Any, ClassVar

import pymongo
import pymongo.errors
from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase
from pymongo.errors import PyMongoError

from eduid.userdb.db.base import BaseMongoDB
from eduid.userdb.exceptions import EduIDUserDBError, MongoConnectionError, MultipleDocumentsReturned

__author__ = "lundberg"

logger = logging.getLogger(__name__)
extra_logger = logger.getChild("extra_debug")


class AsyncClientCache:
    """
    A cache for AsyncIOMotorClient instances.
    """

    _clients: ClassVar[dict[str, AsyncIOMotorClient]] = {}

    def get_client(self, db: BaseMongoDB) -> AsyncIOMotorClient:
        db_args = db.db_args
        connection_uri: str = db_args["host"]
        if connection_uri in self._clients:
            logger.debug(f"Reusing existing connection to {db}")
            return self._clients[connection_uri]
        else:
            logger.debug(f"Creating new connection to {db}")
            client = AsyncIOMotorClient(**db_args)
            self._clients[connection_uri] = client
            return client


class AsyncMongoDB(BaseMongoDB):
    def __init__(
        self,
        db_uri: str,
        db_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(db_uri=db_uri, db_name=db_name, **kwargs)
        try:
            self._client = AsyncClientCache().get_client(self)
        except PyMongoError as e:
            raise MongoConnectionError(f"Error connecting to mongodb {self!r}: {e}") from e

    def get_connection(self) -> AsyncIOMotorClient:
        """
        Get the raw pymongo connection object.
        :return: Pymongo connection object
        """
        return self._client

    def get_database(self, database_name: str | None = None) -> AsyncIOMotorDatabase:
        """
        Get a pymongo database handle.

        :param database_name: (optional) Name of database
        :return: Pymongo database object
        """
        if database_name is None:
            database_name = self._database_name
        if database_name is None:
            raise ValueError("No database_name supplied, and no default provided to __init__")
        return self._client[database_name]

    def get_collection(self, collection: str, database_name: str | None = None) -> AsyncIOMotorCollection:
        """
        Get a pymongo collection handle.

        :param collection: Name of collection
        :param database_name: (optional) Name of database
        :return: Pymongo collection object
        """
        _db = self.get_database(database_name)
        return _db[collection]

    async def is_healthy(self) -> bool:
        """
        From mongo_client.py:
        Starting with version 3.0 the :class:`MongoClient`
        constructor no longer blocks while connecting to the server or
        servers, and it no longer raises
        :class:`~pymongo.errors.ConnectionFailure` if they are
        unavailable, nor :class:`~pymongo.errors.ConfigurationError`
        if the user's credentials are wrong. Instead, the constructor
        returns immediately and launches the connection process on
        background threads. You can check if the server is available
        like this::

        from pymongo.errors import ConnectionFailure
        client = MongoClient()
        try:
            # The ismaster command is cheap and does not require auth.
            client.admin.command('ismaster')
        except ConnectionFailure:
            print("Server not available")

        :return: MongoDB health status
        :rtype: boolean
        """
        try:
            await self.get_connection().admin.command("ismaster")
            return True
        except pymongo.errors.ConnectionFailure as e:
            logger.error(f"{self} not healthy: {e}")
            return False

    async def close(self) -> None:
        self._client.close()


class AsyncBaseDB:
    """Base class for common db operations"""

    def __init__(
        self,
        db_uri: str,
        db_name: str,
        collection: str,
        safe_writes: bool = False,
    ) -> None:
        self._db_uri = db_uri
        self._coll_name = collection
        self._db = AsyncMongoDB(db_uri, db_name=db_name)
        self._coll = self._db.get_collection(collection)
        if safe_writes:
            self._coll = self._coll.with_options(write_concern=pymongo.WriteConcern(w="majority"))

    def __repr__(self) -> str:
        return f"<eduID {self.__class__.__name__!s}: {self._db.sanitized_uri!s} {self._coll_name!r}>"

    __str__ = __repr__

    @property
    def database(self) -> AsyncIOMotorDatabase:
        return self._db.get_database()

    @property
    def collection(self) -> AsyncIOMotorCollection:
        return self._coll

    @property
    def connection(self) -> AsyncIOMotorClient:
        return self._db.get_connection()

    async def _drop_whole_collection(self) -> None:
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logger.warning(f"{self!s} Dropping collection {self._coll_name!r}")
        return await self._coll.drop()

    async def _get_document_by_attr(self, attr: str, value: object) -> Mapping[str, Any] | None:
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :return: A document dict
        """
        if value is None:
            raise EduIDUserDBError(f"Missing value to filter by {attr}")

        docs = await self._coll.find({attr: value}).to_list(length=2)
        doc_count = len(docs)
        if doc_count == 0:
            return None
        elif doc_count > 1:
            raise MultipleDocumentsReturned(f"Multiple matching documents for {attr}={value!r}")
        return docs[0]

    async def _get_documents_by_attr(self, attr: str, value: str) -> list[Mapping[str, Any]]:
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :return: A list of document dicts
        :raise DocumentDoesNotExist: No document matching the search criteria
        """
        docs = await self._coll.find({attr: value}).to_list(length=None)
        doc_count = len(docs)
        if doc_count == 0:
            return []
        return docs

    async def _get_documents_by_aggregate(
        self, match: Mapping[str, Any], sort: Mapping[str, Any] | None = None, limit: int | None = None
    ) -> list[Mapping[str, Any]]:
        pipeline: list[dict[str, Any]] = [{"$match": match}]

        if sort is not None:
            pipeline.append({"$sort": sort})

        if limit is not None:
            pipeline.append({"$limit": limit})

        return await self._coll.aggregate(pipeline=pipeline).to_list(length=None)

    async def _get_documents_by_filter(
        self,
        spec: Mapping[str, Any],
        fields: Mapping[str, Any] | None = None,
        skip: int | None = None,
        limit: int | None = None,
    ) -> list[Mapping[str, Any]]:
        """
        Locate documents in the db using a custom search filter.

        :param spec: the search filter
        :param fields: the fields to return in the search result
        :param skip: Number of documents to skip before returning result
        :param limit: Limit documents returned to this number
        :return: A list of documents
        """
        if fields is not None:
            cursor = self._coll.find(spec, fields)
        else:
            cursor = self._coll.find(spec)

        if skip is not None:
            cursor = cursor.skip(skip=skip)
        if limit is not None:
            cursor = cursor.limit(limit=limit)

        docs = await cursor.to_list(length=None)
        doc_count = len(docs)
        if doc_count == 0:
            return []
        return docs

    async def db_count(self, spec: Mapping[str, Any] | None = None, limit: int | None = None) -> int:
        """
        Return number of entries in the collection.

        :return: Document count
        """
        _filter: Mapping[str, Any] = {}
        if spec:
            _filter = spec

        args: dict[str, Any] = {}
        if limit:
            args["limit"] = limit
        return await self._coll.count_documents(filter=_filter, **args)

    async def remove_document(self, spec_or_id: Mapping[str, Any] | ObjectId) -> bool:
        """
        Remove a document in the db given the _id or dict spec.

        :param spec_or_id: spec or document id (_id)
        """
        _filter: Mapping[str, Any] = {}
        if isinstance(spec_or_id, ObjectId):
            _filter = {"_id": spec_or_id}
        else:
            _filter = spec_or_id
        if not _filter:
            raise RuntimeError("Refusing to remove documents without a spec_or_id")
        result = await self._coll.delete_one(filter=_filter)
        return result.acknowledged

    async def is_healthy(self) -> bool:
        """
        :return: DB health status
        """
        return await self._db.is_healthy()

    async def setup_indexes(self, indexes: Mapping[str, Any]) -> None:
        """
        To update an index add a new item in indexes and remove the previous version.
        """
        # indexes={'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}, }  # noqa: ERA001
        # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
        default_indexes = ["_id_"]  # _id_ index can not be deleted from a mongo collection
        current_indexes = await self._coll.index_information()
        for name in current_indexes:
            if name not in indexes and name not in default_indexes:
                await self._coll.drop_index(name)
        for name, params in indexes.items():
            if name not in current_indexes:
                key = params.pop("key")
                params["name"] = name
                await self._coll.create_index(key, **params)

    async def close(self) -> None:
        await self._db.close()
