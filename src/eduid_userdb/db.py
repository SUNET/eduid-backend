import copy
import pymongo
import logging
from .exceptions import (DocumentDoesNotExist, MultipleDocumentsReturned,
                         MongoConnectionError)


class MongoDB(object):
    """Simple wrapper to get pymongo real objects from the settings uri"""

    def __init__(self, db_uri, db_name=None,
                 connection_factory=None, **kwargs):

        if db_uri is None:
            raise ValueError('db_uri not supplied')

        self._db_uri = db_uri
        self._database_name = db_name
        self._sanitized_uri = None

        self._parsed_uri = pymongo.uri_parser.parse_uri(db_uri)

        if self._parsed_uri.get('database') is None:
            self._parsed_uri['database'] = db_name

        if 'replicaSet' in kwargs and kwargs['replicaSet'] is None:
            del kwargs['replicaSet']

        _options = self._parsed_uri.get('options')
        if connection_factory is None:
            connection_factory = pymongo.MongoClient
        if 'replicaSet' in kwargs:
            connection_factory = pymongo.MongoReplicaSetClient
        if 'replicaSet' in _options and _options['replicaSet'] is not None:
            connection_factory = pymongo.MongoReplicaSetClient
            kwargs['replicaSet'] = _options['replicaSet']

        if 'replicaSet' in kwargs:
            if 'socketTimeoutMS' not in kwargs:
                kwargs['socketTimeoutMS'] = 5000
            if 'connectTimeoutMS' not in kwargs:
                kwargs['connectTimeoutMS'] = 5000

        self._db_uri = _format_mongodb_uri(self._parsed_uri)

        try:
            self._connection = connection_factory(
                host=self._db_uri,
                tz_aware=True,
                **kwargs)
        except pymongo.errors.PyMongoError as e:
            raise MongoConnectionError('Error connecting to mongodb {!r}: {}'.format(self, e))

    def __repr__(self):
        return '<eduID {!s}: {!s} {!s}>'.format(self.__class__.__name__,
                                                self._db_uri,
                                                self._database_name)

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

    def get_database(self, database_name=None, username=None, password=None):
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
            db.authenticate(
                self._parsed_uri.get("username", None),
                self._parsed_uri.get("password", None)
            )
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

    def close(self):
        self._connection.close()


def _format_mongodb_uri(parsed_uri):
    """
    Painstakenly reconsttruct a MongoDB URI parsed using pymongo.uri_parser.parse_uri.

    :param parsed_uri: Result of pymongo.uri_parser.parse_uri
    :type parsed_uri: dict

    :return: New URI
    :rtype: str | unicode
    """
    user_pass = ''
    if parsed_uri.get('username') and parsed_uri.get('password'):
        user_pass = '{username!s}:{password!s}@'.format(**parsed_uri)

    _nodes = []
    for host, port in parsed_uri.get('nodelist'):
        if ':' in host and not host.endswith(']'):
            # IPv6 address without brackets
            host = '[{!s}]'.format(host)
        if port == 27017:
            _nodes.append(host)
        else:
            _nodes.append('{!s}:{!s}'.format(host, port))
    nodelist = ','.join(_nodes)

    options = ''
    if parsed_uri.get('options'):
        _opt_list = []
        for key, value in parsed_uri.get('options').items():
            if isinstance(value, bool):
                value = str(value).lower()
            _opt_list.append('{!s}={!s}'.format(key, value))
        options = '?' + '&'.join(sorted(_opt_list))

    db_name = parsed_uri.get('database') or ''

    res = "mongodb://{user_pass!s}{nodelist!s}/{db_name!s}{options!s}".format(
        user_pass = user_pass,
        nodelist = nodelist,
        db_name = db_name,
        # collection is ignored
        options = options)
    return res


class BaseDB(object):
    """ Base class for common db operations """

    def __init__(self, db_uri, db_name, collection, safe_writes=False):

        self._db_uri = db_uri
        self._coll_name = collection
        self._db = MongoDB(db_uri, db_name=db_name)
        self._coll = self._db.get_collection(collection)
        if safe_writes:
            self._coll = self._coll.with_options(write_concern = pymongo.WriteConcern(w = 'majority'))


    def __repr__(self):
        return '<eduID {!s}: {!s} {!r}>'.format(self.__class__.__name__,
                                                self._db.sanitized_uri,
                                                self._coll_name)

    def _drop_whole_collection(self):
        """
        Drop the whole collection. Should ONLY be used in testing, obviously.
        :return:
        """
        logging.warning("{!s} Dropping collection {!r}".format(self, self._coll_name))
        return self._coll.drop()

    def _get_all_docs(self):
        """
        Return all the user documents in the database.

        Used in eduid-dashboard test cases.

        :return: User documents
        :rtype:
        """
        return self._coll.find({})

    def _get_document_by_attr(self, attr, value, raise_on_missing=True):
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :type attr: str
        :param value: The field value
        :type value: str
        :param raise_on_missing:  If True, raise exception if no matching user object can be found.
        :type raise_on_missing: bool
        :return: A document dict
        :rtype: dict | None
        """
        docs = self._coll.find({attr: value})
        if docs.count() == 0:
            if raise_on_missing:
                raise DocumentDoesNotExist("No document matching %s='%s'" % (attr, value))
            return None
        elif docs.count() > 1:
            raise MultipleDocumentsReturned("Multiple matching documents for %s='%s'" % (attr, value))
        return docs[0]

    def _get_documents_by_attr(self, attr, value, raise_on_missing=True):
        """
        Return the document in the MongoDB matching field=value

        :param attr: The name of a field
        :type attr: str
        :param value: The field value
        :type value: str
        :param raise_on_missing:  If True, raise exception if no matching user object can be found.
        :type raise_on_missing: bool
        :return: A document dict
        :rtype: cursor | []
        :raise DocumentDoesNotExist: No document matching the search criteria
        """
        docs = self._coll.find({attr: value})
        if docs.count() == 0:
            if raise_on_missing:
                raise DocumentDoesNotExist("No document matching %s='%s'" % (attr, value))
            return []
        return docs

    def _get_documents_by_filter(self, spec, fields=None, raise_on_missing=True):
        """
        Locate a documents in the db using a custom search filter.

        :param spec: the search filter
        :type spec: dict
        :param fields: the fields to return in the search result
        :type fields: dict
        :return: A document dict
        :rtype: cursor | []
        :raise DocumentDoesNotExist: No document matching the search criteria
        """
        if fields is None:
            docs = self._coll.find(spec)
        else:
            docs = self._coll.find(spec, fields)
        if docs.count() == 0:
            if raise_on_missing:
                raise DocumentDoesNotExist('No document matching {!s}'.format(spec))
            return []
        return docs

    def db_count(self):
        """
        Return number of entries in the database.

        Used in test cases.

        :return: User count
        :rtype: int
        """
        return self._coll.find({}).count()

    def remove_document(self, spec_or_id):
        """
        Remove a document in the db given the _id or dict spec.

        :param spec_or_id: spec or document id (_id)
        :type spec_or_id: dict | bson.ObjectId
        """
        return self._coll.remove(spec_or_id=spec_or_id)

    def setup_indexes(self, indexes):
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

