import copy

import pymongo


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

        _options = self._parsed_uri.get('options')
        if connection_factory is None:
            connection_factory = pymongo.MongoClient
        if 'replicaSet' in kwargs:
            connection_factory = pymongo.MongoReplicaSetClient
        if 'replicaSet' in _options:
            connection_factory = pymongo.MongoReplicaSetClient
            kwargs['replicaSet'] = _options['replicaSet']

        self._db_uri = _format_mongodb_uri(self._parsed_uri)

        self._connection = connection_factory(
            host=self._db_uri,
            tz_aware=True,
            **kwargs)

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
        options = '?' + '&'.join(_opt_list)

    db_name = parsed_uri.get('database') or ''

    res = "mongodb://{user_pass!s}{nodelist!s}/{db_name!s}{options!s}".format(
        user_pass = user_pass,
        nodelist = nodelist,
        db_name = db_name,
        # collection is ignored
        options = options)
    return res
