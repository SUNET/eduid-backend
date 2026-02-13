import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import pymongo
import pymongo.collection
import pymongo.cursor
import pymongo.errors
from bson import ObjectId
from pymongo.database import Database
from pymongo.errors import PyMongoError

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.db.base import BaseMongoDB, TUserDbDocument
from eduid.userdb.exceptions import DocumentOutOfSync, EduIDUserDBError, MongoConnectionError, MultipleDocumentsReturned
from eduid.userdb.meta import Meta
from eduid.userdb.util import format_dict_for_debug

logger = logging.getLogger(__name__)
extra_logger = logger.getChild("extra_debug")


class MongoClientCache:
    """
    A cache for pymongo.MongoClient instances.
    """

    _clients: dict[str, pymongo.MongoClient] = {}

    def get_client(self, db: BaseMongoDB) -> pymongo.MongoClient:
        db_args = db.db_args
        connection_uri: str = db_args["host"]
        if connection_uri in self._clients:
            logger.debug(f"Reusing existing connection to {db}")
            return self._clients[connection_uri]
        else:
            logger.debug(f"Creating new connection to {db}")
            client = pymongo.MongoClient[TUserDbDocument](**db_args)
            self._clients[connection_uri] = client
            return client


class MongoDB(BaseMongoDB):
    def __init__(
        self,
        db_uri: str,
        db_name: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(db_uri=db_uri, db_name=db_name, **kwargs)
        try:
            self._client = MongoClientCache().get_client(db=self)

        except PyMongoError as e:
            raise MongoConnectionError(f"Error connecting to mongodb {self!r}: {e}") from e

    def get_connection(self) -> pymongo.MongoClient[TUserDbDocument]:
        """
        Get the raw pymongo connection object.
        :return: Pymongo connection object
        """
        return self._client

    def get_database(self, database_name: str | None = None) -> Database[TUserDbDocument]:
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

    def get_collection(
        self, collection: str, database_name: str | None = None
    ) -> pymongo.collection.Collection[TUserDbDocument]:
        """
        Get a pymongo collection handle.

        :param collection: Name of collection
        :param database_name: (optional) Name of database
        :return: Pymongo collection object
        """
        _db = self.get_database(database_name)
        return _db[collection]

    def is_healthy(self) -> bool:
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
            self.get_connection().admin.command("ismaster")
            return True
        except pymongo.errors.ConnectionFailure as e:
            logger.error(f"{self} not healthy: {e}")
            return False

    def close(self) -> None:
        self._client.close()


@dataclass
class SaveResult:
    """
    Result of a save operation.

    :param inserted: Number of inserted documents
    :param updated: Number of updated documents
    :param doc_id: The _id of the inserted/updated document
    """

    ts: datetime
    inserted: int = 0
    updated: int = 0
    doc_id: ObjectId | None = None

    def __bool__(self) -> bool:
        return bool(self.inserted or self.updated)


class BaseDB:
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
        self._db = MongoDB(db_uri, db_name=db_name)
        self._coll = self._db.get_collection(collection)
        if safe_writes:
            self._coll = self._coll.with_options(write_concern=pymongo.WriteConcern(w="majority"))

    def __repr__(self) -> str:
        return f"<eduID {self.__class__.__name__!s}: {self._db.sanitized_uri!s} {self._coll_name!r}>"

    __str__ = __repr__

    def _drop_whole_collection(self) -> None:
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logger.warning(f"{self!s} Dropping collection {self._coll_name!r}")
        return self._coll.drop()

    def _get_all_docs(self) -> pymongo.cursor.Cursor[TUserDbDocument]:
        """
        Return all the user documents in the database.

        Used in eduid-dashboard test cases.

        :return: User documents
        """
        return self._coll.find({})

    def _get_document_by_attr(self, attr: str, value: Any) -> TUserDbDocument | None:  # noqa: ANN401
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :return: A document dict
        """
        if value is None:
            raise EduIDUserDBError(f"Missing value to filter users by {attr}")

        docs = list(self._coll.find({attr: value}))
        doc_count = len(docs)
        if doc_count == 0:
            return None
        elif doc_count > 1:
            raise MultipleDocumentsReturned(f"Multiple matching documents for {attr}={value!r}")
        return docs[0]

    def _get_documents_by_attr(self, attr: str, value: str) -> list[TUserDbDocument]:
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :return: A list of document dicts
        :raise DocumentDoesNotExist: No document matching the search criteria
        """
        docs = list(self._coll.find({attr: value}))
        doc_count = len(docs)
        if doc_count == 0:
            return []
        return docs

    def _get_documents_by_aggregate(
        self, match: Mapping[str, Any], sort: Mapping[str, Any] | None = None, limit: int | None = None
    ) -> list[TUserDbDocument]:
        pipeline: list[dict[str, Any]] = [{"$match": match}]

        if sort is not None:
            pipeline.append({"$sort": sort})

        if limit is not None:
            pipeline.append({"$limit": limit})

        return list(self._coll.aggregate(pipeline=pipeline))

    def _get_documents_by_filter(
        self,
        spec: Mapping[str, Any],
        fields: Mapping[str, Any] | None = None,
        skip: int | None = None,
        limit: int | None = None,
    ) -> list[TUserDbDocument]:
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

        docs = list(cursor)
        doc_count = len(docs)
        if doc_count == 0:
            return []
        return docs

    def db_count(self, spec: Mapping[str, Any] | None = None, limit: int | None = None) -> int:
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
        return self._coll.count_documents(filter=_filter, **args)

    def remove_document(self, spec_or_id: Mapping[str, Any] | ObjectId) -> bool:
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
        result = self._coll.delete_one(filter=_filter)
        return result.acknowledged

    def is_healthy(self) -> bool:
        """
        :return: DB health status
        """
        return self._db.is_healthy()

    def setup_indexes(self, indexes: Mapping[str, Any]) -> None:
        """
        To update an index add a new item in indexes and remove the previous version.
        """
        # indexes={'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}, }  # noqa: ERA001
        # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
        default_indexes = ["_id_"]  # _id_ index can not be deleted from a mongo collection
        current_indexes = self._coll.index_information()
        for name in current_indexes:
            if name not in indexes and name not in default_indexes:
                self._coll.drop_index(name)
        for name, params in indexes.items():
            if name not in current_indexes:
                key = params.pop("key")
                params["name"] = name
                self._coll.create_index(key, **params)

    def _save(
        self,
        data: TUserDbDocument,
        spec: Mapping[str, Any],
        is_in_database: bool,
        meta: Meta | None = None,
    ) -> SaveResult:
        """
        Save a document in the db.

        BaseDB works with documents, not with userdb objects. This becomes a bit messy since
        this code updates the document and the calling code has to update the userdb object.

        TODO: 1. Add Meta to all objects. This removes the need for is_in_database.
              2. Remove modified_ts from the root of the document.
        """
        previous_version = None
        previous_ts = data.get("modified_ts")
        now = utc_now()

        if meta is not None:
            previous_version = meta.version
            is_in_database = meta.is_in_database
            # Update meta
            meta.new_version()
            meta.modified_ts = now
            data["meta"] = meta.model_dump()

            logger.debug(f"{self} Saving document (version {previous_version} -> {meta.version})")
        else:
            logger.debug(f"{self} Saving document without meta (modified_ts {previous_ts} -> {now.isoformat()})")

        extra_logger.debug(f"{self} Extra debug: Full document:\n {format_dict_for_debug(data)}")

        data["modified_ts"] = now  # update modified_ts (old) to current time

        if not is_in_database:
            # This is a new document, insert it
            if meta is not None:
                logger.debug(f"{self} Inserting new document with version {meta.version}")
            else:
                logger.debug(f"{self} Inserting new document without meta  (modified_ts {now})")
            try:
                insert_result = self._coll.insert_one(data)
            except pymongo.errors.DuplicateKeyError:
                # Log failure and raise DocumentOutOfSync exception
                db_doc = self._get_and_format_existing_doc_for_logging(spec)
                logger.error(
                    f"{self} FAILED inserting new document.\nLoad with spec:\n{format_dict_for_debug(spec)}\n"
                    f"In database:\n{db_doc}\n)"
                )
                raise

            save_result = SaveResult(inserted=1, doc_id=insert_result.inserted_id, ts=now)
            logger.debug(f"{self} Inserted new document into {self._coll_name}): {save_result})")
            if meta is not None:
                meta.is_in_database = True
            return save_result

        #
        # Update an existing document
        #
        replace_spec = dict(spec)
        if previous_ts is not None:
            replace_spec["modified_ts"] = previous_ts
        if previous_version is not None:
            replace_spec["meta.version"] = previous_version

        extra_logger.debug(f"{self} Extra debug: replacing document using spec:\n{format_dict_for_debug(replace_spec)}")

        update_result = self._coll.replace_one(replace_spec, data)
        save_result = SaveResult(updated=update_result.modified_count, doc_id=data["_id"], ts=now)

        if update_result.matched_count == 0:
            # Log failure and raise DocumentOutOfSync exception
            db_doc = self._get_and_format_existing_doc_for_logging(spec)
            logger.error(
                f"{self} FAILED updating document\n{format_dict_for_debug(replace_spec)}\n"
                f"with is_in_database={is_in_database}\nLoad with spec\n{format_dict_for_debug(spec)}\n"
                f"In database:\n{db_doc}\n): {save_result}"
            )

            raise DocumentOutOfSync("Stale document can't be saved")

        logger.debug(f"{self} Updated document {replace_spec} (ts {now.isoformat()}): {save_result}")
        return save_result

    def _get_and_format_existing_doc_for_logging(self, spec: Mapping[str, Any]) -> str | None:
        db_doc = {}
        db_state = self._coll.find_one(spec)
        if not db_state:
            return "No document found"

        db_doc["modified_ts"] = db_state.get("modified_ts")
        db_doc["meta"] = db_state.get("meta")
        return format_dict_for_debug(db_doc)

    def close(self) -> None:
        self._db.close()
