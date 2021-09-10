import copy
import logging
import warnings
from typing import Any, Dict, List, Mapping, Optional, Union

import pymongo
from bson import ObjectId
from pymongo.errors import PyMongoError
from pymongo.uri_parser import parse_uri

from eduid.userdb.exceptions import EduIDUserDBError, MongoConnectionError, MultipleDocumentsReturned


class MongoDB(object):
    """Simple wrapper to get pymongo real objects from the settings uri"""

    def __init__(self, db_uri, db_name=None, connection_factory=None, **kwargs):
        if db_uri is None:
            raise ValueError('db_uri not supplied')

        self._db_uri = db_uri
        self._database_name = db_name
        self._sanitized_uri = None

        self._parsed_uri = parse_uri(db_uri)

        if self._parsed_uri.get('database') is None:
            self._parsed_uri['database'] = db_name

        if 'replicaSet' in kwargs and kwargs['replicaSet'] is None:
            del kwargs['replicaSet']

        _options = self._parsed_uri.get('options')
        if connection_factory is None:
            connection_factory = pymongo.MongoClient
        elif connection_factory == pymongo.MongoReplicaSetClient:
            warnings.warn(
                f'{__name__} initialized with connection_factory {connection_factory} use pymongo.MongoClient instead.',
                DeprecationWarning,
            )
        elif connection_factory.__class__.__name__ == 'AsyncIOMotorClient':
            from motor import motor_asyncio

            connection_factory = motor_asyncio.AsyncIOMotorClient

        if 'replicaSet' in _options and _options['replicaSet'] is not None:
            kwargs['replicaSet'] = _options['replicaSet']

        if 'replicaSet' in kwargs:
            if 'socketTimeoutMS' not in kwargs:
                kwargs['socketTimeoutMS'] = 5000
            if 'connectTimeoutMS' not in kwargs:
                kwargs['connectTimeoutMS'] = 5000

        self._db_uri = _format_mongodb_uri(self._parsed_uri)

        try:
            self._connection = connection_factory(host=self._db_uri, tz_aware=True, **kwargs)
        except PyMongoError as e:
            raise MongoConnectionError('Error connecting to mongodb {!r}: {}'.format(self, e))

    def __repr__(self):
        return '<eduID {!s}: {!s} {!s}>'.format(
            self.__class__.__name__, getattr(self, '_db_uri', None), getattr(self, '_database_name', None)
        )

    __str__ = __repr__

    @property
    def sanitized_uri(self):
        """
        Return the database URI we're using in a format sensible for logging etc.

        :return: db_uri
        """
        if self._sanitized_uri is None:
            _parsed = copy.copy(self._parsed_uri)
            if 'username' in _parsed:
                _parsed['password'] = 'secret'
            _parsed['nodelist'] = [_parsed['nodelist'][0]]
            self._sanitized_uri = _format_mongodb_uri(_parsed)
        return self._sanitized_uri

    def get_connection(self):
        """
        Get the raw pymongo connection object.
        :return: Pymongo connection object
        """
        return self._connection

    def get_database(
        self, database_name: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None
    ):
        """
        Get a pymongo database handle, after authenticating.

        Authenticates using the username/password in the DB URI given to
        __init__() unless username/password is supplied as arguments.

        :param database_name: (optional) Name of database
        :param username: (optional) Username to login with
        :param password: (optional) Password to login with
        :return: Pymongo database object
        """
        if database_name is None:
            database_name = self._database_name
        if database_name is None:
            raise ValueError('No database_name supplied, and no default provided to __init__')
        db = self._connection[database_name]
        if username and password:
            db.authenticate(username, password)
        elif self._parsed_uri.get("username", None):
            db.authenticate(self._parsed_uri.get("username", None), self._parsed_uri.get("password", None))
        return db

    def get_collection(self, collection, database_name=None, username=None, password=None):
        """
        Get a pymongo collection handle.

        :param collection: Name of collection
        :param database_name: (optional) Name of database
        :param username: (optional) Username to login with
        :param password: (optional) Password to login with
        :return: Pymongo collection object
        """
        _db = self.get_database(database_name, username, password)
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
            self.get_connection().admin.command('ismaster')
            return True
        except pymongo.errors.ConnectionFailure as e:
            logging.error('{} not healthy: {}'.format(self, e))
            return False

    def close(self):
        self._connection.close()


def _format_mongodb_uri(parsed_uri: Mapping[str, Any]) -> str:
    """
    Painstakingly reconstruct a MongoDB URI parsed using pymongo.uri_parser.parse_uri.

    :param parsed_uri: Result of pymongo.uri_parser.parse_uri

    :return: New URI
    """
    user_pass = ''
    if parsed_uri.get('username') and parsed_uri.get('password'):
        user_pass = '{username!s}:{password!s}@'.format(**parsed_uri)

    _nodes = []
    for host, port in parsed_uri.get('nodelist', []):
        if ':' in host and not host.endswith(']'):
            # IPv6 address without brackets
            host = '[{!s}]'.format(host)
        if port == 27017:
            _nodes.append(host)
        else:
            _nodes.append('{!s}:{!s}'.format(host, port))
    nodelist = ','.join(_nodes)

    _opt_list = []
    for key, value in parsed_uri.get('options', {}).items():
        if isinstance(value, bool):
            value = str(value).lower()
        _opt_list.append('{!s}={!s}'.format(key, value))

    options = ''
    if _opt_list:
        options = '?' + '&'.join(sorted(_opt_list))

    db_name = parsed_uri.get('database') or ''

    res = "mongodb://{user_pass!s}{nodelist!s}/{db_name!s}{options!s}".format(
        user_pass=user_pass,
        nodelist=nodelist,
        db_name=db_name,
        # collection is ignored
        options=options,
    )
    return res


class BaseDB(object):
    """ Base class for common db operations """

    def __init__(self, db_uri: str, db_name: str, collection: str, safe_writes: bool = False):

        self._db_uri = db_uri
        self._coll_name = collection
        self._db = MongoDB(db_uri, db_name=db_name)
        self._coll = self._db.get_collection(collection)
        if safe_writes:
            self._coll = self._coll.with_options(write_concern=pymongo.WriteConcern(w='majority'))

    def __repr__(self):
        return '<eduID {!s}: {!s} {!r}>'.format(self.__class__.__name__, self._db.sanitized_uri, self._coll_name)

    __str__ = __repr__

    def _drop_whole_collection(self):
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logging.warning("{!s} Dropping collection {!r}".format(self, self._coll_name))
        return self._coll.drop()

    def _get_all_docs(self) -> List[Dict[str, Any]]:
        """
        Return all the user documents in the database.

        Used in eduid-dashboard test cases.

        :return: User documents
        """
        return self._coll.find({})

    def _get_document_by_attr(self, attr: str, value: str) -> Optional[Dict[str, Any]]:
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :param value: The field value
        :return: A document dict
        """
        if value is None:
            raise EduIDUserDBError(f'Missing value to filter users by {attr}')

        docs = list(self._coll.find({attr: value}))
        doc_count = len(docs)
        if doc_count == 0:
            return None
        elif doc_count > 1:
            raise MultipleDocumentsReturned(f'Multiple matching documents for {attr}={repr(value)}')
        return docs[0]

    def _get_documents_by_attr(self, attr: str, value: str) -> List[Dict[str, Any]]:
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

    def _get_documents_by_filter(
        self,
        spec: Mapping[str, Any],
        fields: Optional[dict] = None,
        skip: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> List[Mapping]:
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
        args: Dict[str, Any] = {'filter': {}}
        if spec:
            args['filter'] = spec
        if limit:
            args['limit'] = limit
        return self._coll.count_documents(**args)

    def remove_document(self, spec_or_id: Union[dict, ObjectId]) -> bool:
        """
        Remove a document in the db given the _id or dict spec.

        :param spec_or_id: spec or document id (_id)
        """
        if isinstance(spec_or_id, ObjectId):
            spec_or_id = {'_id': spec_or_id}
        result = self._coll.delete_one(spec_or_id)
        return result.acknowledged

    def is_healthy(self) -> bool:
        """
        :return: DB health status
        """
        return self._db.is_healthy()

    def setup_indexes(self, indexes: Dict[str, Any]):
        """
        To update an index add a new item in indexes and remove the previous version.
        """
        # indexes={'index-name': {'key': [('key', 1)], 'param1': True, 'param2': False}, }
        # http://docs.mongodb.org/manual/reference/method/db.collection.ensureIndex/
        default_indexes = ['_id_']  # _id_ index can not be deleted from a mongo collection
        current_indexes = self._coll.index_information()
        for name in current_indexes:
            if name not in indexes and name not in default_indexes:
                self._coll.drop_index(name)
        for name, params in indexes.items():
            if name not in current_indexes:
                key = params.pop('key')
                params['name'] = name
                self._coll.ensure_index(key, **params)

    def close(self):
        self._db.close()
