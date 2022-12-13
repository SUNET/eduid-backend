import copy
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, NewType, Optional, TypeVar, Union

import pymongo
import pymongo.collection
import pymongo.cursor
import pymongo.errors
from bson import ObjectId
from pymongo.database import Database
from pymongo.errors import PyMongoError
from pymongo.uri_parser import parse_uri

from eduid.userdb.exceptions import DocumentOutOfSync, EduIDUserDBError, MongoConnectionError, MultipleDocumentsReturned
from eduid.userdb.util import format_dict_for_debug, utc_now

logger = logging.getLogger(__name__)
extra_logger = logger.getChild("extra")

if TYPE_CHECKING:
    from motor import motor_asyncio

TUserDbDocument = NewType("TUserDbDocument", dict[str, Any])

TMongoClient = TypeVar(
    "TMongoClient",
    pymongo.MongoClient[TUserDbDocument],
    "motor_asyncio.AsyncIOMotorClient",
)


class DatabaseDriver(Enum):
    CLASSIC = "classic"
    ASYNCIO = "asyncio"


class MongoDB(object):
    """Simple wrapper to get pymongo real objects from the settings uri"""

    def __init__(
        self,
        db_uri: str,
        db_name: Optional[str] = None,
        driver: Optional[DatabaseDriver] = None,
        **kwargs: Any,
    ):
        if db_uri is None:
            raise ValueError("db_uri not supplied")

        self._db_uri: str = db_uri
        self._database_name: Optional[str] = db_name
        self._sanitized_uri: Optional[str] = None

        self._parsed_uri = parse_uri(db_uri)

        if self._parsed_uri.get("database") is None:
            self._parsed_uri["database"] = db_name

        if "replicaSet" in kwargs and kwargs["replicaSet"] is None:
            del kwargs["replicaSet"]

        _options = self._parsed_uri.get("options")
        assert _options is not None  # please mypy

        if "replicaSet" in _options and _options["replicaSet"] is not None:
            kwargs["replicaSet"] = _options["replicaSet"]

        if "replicaSet" in kwargs:
            if "socketTimeoutMS" not in kwargs:
                kwargs["socketTimeoutMS"] = 5000
            if "connectTimeoutMS" not in kwargs:
                kwargs["connectTimeoutMS"] = 5000

        self._db_uri = _format_mongodb_uri(self._parsed_uri)

        try:
            db_args = dict(
                host=self._db_uri,
                tz_aware=True,
                # TODO: switch uuidRepresentation to "standard" when we made sure all UUIDs are stored as strings
                uuidRepresentation="pythonLegacy",
                **kwargs,
            )
            self._client: pymongo.MongoClient[TUserDbDocument]
            if driver is None or driver == DatabaseDriver.CLASSIC:
                self._client = pymongo.MongoClient[TUserDbDocument](**db_args)
            else:
                from motor import motor_asyncio

                self._client = motor_asyncio.AsyncIOMotorClient(**db_args)
        except PyMongoError as e:
            raise MongoConnectionError("Error connecting to mongodb {!r}: {}".format(self, e))

    def __repr__(self):
        return "<eduID {!s}: {!s} {!s}>".format(
            self.__class__.__name__, getattr(self, "_db_uri", None), getattr(self, "_database_name", None)
        )

    __str__ = __repr__

    @property
    def sanitized_uri(self) -> str:
        """
        Return the database URI we're using in a format sensible for logging etc.

        :return: db_uri
        """
        if self._sanitized_uri is None:
            _parsed = copy.copy(self._parsed_uri)
            if "username" in _parsed:
                _parsed["password"] = "secret"
            _parsed["nodelist"] = [_parsed["nodelist"][0]]
            self._sanitized_uri = _format_mongodb_uri(_parsed)
        return self._sanitized_uri

    def get_connection(self) -> pymongo.MongoClient[TUserDbDocument]:
        """
        Get the raw pymongo connection object.
        :return: Pymongo connection object
        """
        return self._client

    def get_database(self, database_name: Optional[str] = None) -> Database[TUserDbDocument]:
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
        self, collection: str, database_name: Optional[str] = None
    ) -> pymongo.collection.Collection[TUserDbDocument]:
        """
        Get a pymongo collection handle.

        :param collection: Name of collection
        :param database_name: (optional) Name of database
        :return: Pymongo collection object
        """
        _db = self.get_database(database_name)
        return _db[collection]

    def is_healthy(self):
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
            logger.error("{} not healthy: {}".format(self, e))
            return False

    def close(self):
        self._client.close()


def _format_mongodb_uri(parsed_uri: Mapping[str, Any]) -> str:
    """
    Painstakingly reconstruct a MongoDB URI parsed using pymongo.uri_parser.parse_uri.

    :param parsed_uri: Result of pymongo.uri_parser.parse_uri

    :return: New URI
    """
    user_pass = ""
    if parsed_uri.get("username") and parsed_uri.get("password"):
        user_pass = "{username!s}:{password!s}@".format(**parsed_uri)

    _nodes: list[str] = []
    for host, port in parsed_uri.get("nodelist", []):
        if ":" in host and not host.endswith("]"):
            # IPv6 address without brackets
            host = "[{!s}]".format(host)
        if port == 27017:
            _nodes.append(host)
        else:
            _nodes.append("{!s}:{!s}".format(host, port))
    nodelist = ",".join(_nodes)

    _opt_list: list[str] = []
    for key, value in parsed_uri.get("options", {}).items():
        if isinstance(value, bool):
            value = str(value).lower()
        _opt_list.append("{!s}={!s}".format(key, value))

    options = ""
    if _opt_list:
        options = "?" + "&".join(sorted(_opt_list))

    db_name = parsed_uri.get("database") or ""

    res = "mongodb://{user_pass!s}{nodelist!s}/{db_name!s}{options!s}".format(
        user_pass=user_pass,
        nodelist=nodelist,
        db_name=db_name,
        # collection is ignored
        options=options,
    )
    return res


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
    doc_id: Optional[ObjectId] = None

    def __bool__(self):
        return bool(self.inserted or self.updated)


class BaseDB(object):
    """Base class for common db operations"""

    def __init__(
        self,
        db_uri: str,
        db_name: str,
        collection: str,
        safe_writes: bool = False,
        driver: Optional[DatabaseDriver] = None,
    ):

        self._db_uri = db_uri
        self._coll_name = collection
        self._db = MongoDB(db_uri, db_name=db_name, driver=driver)
        self._coll = self._db.get_collection(collection)
        if safe_writes:
            self._coll = self._coll.with_options(write_concern=pymongo.WriteConcern(w="majority"))

    def __repr__(self):
        return "<eduID {!s}: {!s} {!r}>".format(self.__class__.__name__, self._db.sanitized_uri, self._coll_name)

    __str__ = __repr__

    def _drop_whole_collection(self):
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logger.warning("{!s} Dropping collection {!r}".format(self, self._coll_name))
        return self._coll.drop()

    def _get_all_docs(self) -> pymongo.cursor.Cursor[TUserDbDocument]:
        """
        Return all the user documents in the database.

        Used in eduid-dashboard test cases.

        :return: User documents
        """
        return self._coll.find({})

    def _get_document_by_attr(self, attr: str, value: Any) -> Optional[TUserDbDocument]:
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
            raise MultipleDocumentsReturned(f"Multiple matching documents for {attr}={repr(value)}")
        return docs[0]

    def _get_documents_by_attr(self, attr: str, value: str) -> List[TUserDbDocument]:
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
        self, match: Mapping[str, Any], sort: Optional[Mapping[str, Any]] = None, limit: Optional[int] = None
    ) -> List[TUserDbDocument]:

        pipeline: List[Dict[str, Any]] = [{"$match": match}]

        if sort is not None:
            pipeline.append({"$sort": sort})

        if limit is not None:
            pipeline.append({"$limit": limit})

        return list(self._coll.aggregate(pipeline=pipeline))

    def _get_documents_by_filter(
        self,
        spec: Mapping[str, Any],
        fields: Optional[Mapping[str, Any]] = None,
        skip: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> List[TUserDbDocument]:
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

    def db_count(self, spec: Optional[Mapping[str, Any]] = None, limit: Optional[int] = None) -> int:
        """
        Return number of entries in the collection.

        :return: Document count
        """
        _filter: Mapping[str, Any] = {}
        if spec:
            _filter = spec

        args: Dict[str, Any] = {}
        if limit:
            args["limit"] = limit
        return self._coll.count_documents(filter=_filter, **args)

    def remove_document(self, spec_or_id: Union[Mapping[str, Any], ObjectId]) -> bool:
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
        # indexes={'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}, }
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

    def legacy_save(self, doc: Dict[str, Any]) -> str:
        """
        Only used in tests and should probably be removed when time allows.
        pymongo removed the save method in version 4.0.
        """
        if "_id" in doc:
            self._coll.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            return doc["_id"]
        res = self._coll.insert_one(doc)  # type: ignore
        return res.inserted_id

    def _save(
        self,
        data: TUserDbDocument,
        spec: Mapping[str, Any],
        check_sync: bool,
        previous_version: Optional[ObjectId] = None,
    ) -> SaveResult:
        """Save a document in the db."""

        previous_ts = data.get("modified_ts")

        _new_version = data.get("meta", {}).get("version", None)
        if _new_version:
            logger.debug(f"{self} Saving document (version {previous_version} -> {_new_version})")

        extra_logger.debug(f"{self} Extra debug: Full document:\n {format_dict_for_debug(data)}")

        now = utc_now()
        data["modified_ts"] = now  # update modified_ts (old) to current time
        if "meta" in data:
            data["meta"]["modified_ts"] = now  # update meta.modified_ts (new) to current time

        if previous_ts is None:
            # This is a new document, insert it
            logger.debug(f"Inserting new document with modified_ts {now.isoformat()}")
            insert_result = self._coll.insert_one(data)
            save_result = SaveResult(inserted=1, doc_id=insert_result.inserted_id, ts=now)
            logger.debug(f"{self} Inserted new document into {self._coll_name}): {save_result})")
            return save_result

        replace_spec = dict(spec)
        if check_sync:
            replace_spec["modified_ts"] = previous_ts
            if previous_version is not None:
                replace_spec["meta.version"] = previous_version

        extra_logger.debug(f"{self} Extra debug: replacing document using spec:\n{format_dict_for_debug(replace_spec)}")

        # TODO: The upsert=(not check_sync) part lets us get away with (test) users having a timestamp
        #       (from instantiation) even though they are not in the database. Could be improved upon.
        update_result = self._coll.replace_one(replace_spec, data, upsert=(not check_sync))
        save_result = SaveResult(updated=update_result.modified_count, doc_id=data["_id"], ts=now)

        if update_result.matched_count == 0:
            # Log failure and raise DocumentOutOfSync exception if check_sync was True
            db_doc = {}
            db_state = self._coll.find_one(spec)
            if db_state:
                db_doc["modified_ts"] = db_state.get("modified_ts")
                db_doc["meta"] = db_state.get("meta")

            logger.error(
                f"{self} FAILED Updating document\n{format_dict_for_debug(replace_spec)}\n"
                f"with check_sync={check_sync} (in db:\n"
                f"{format_dict_for_debug(db_doc)}\n): {save_result}"
            )

            if check_sync:
                raise DocumentOutOfSync("Stale document can't be saved")

        logger.debug(f"{self} Updated document {replace_spec} (ts {now.isoformat()}): {save_result}")
        return save_result

    def close(self):
        self._db.close()
