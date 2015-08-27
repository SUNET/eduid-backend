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

        _options = self._parsed_uri.get('options')
        if 'replicaSet' in kwargs or 'replicaSet' in _options:
            connection_factory = pymongo.MongoReplicaSetClient
        if 'replicaSet' in _options:
            connection_factory = pymongo.MongoReplicaSetClient
            kwargs['replicaSet'] = _options['replicaSet']
        elif connection_factory is None:
            connection_factory = pymongo.MongoClient

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
            userpass = ''
            if self._parsed_uri.get('username') is not None:
                userpass = '{!s}:secret@'.format(self._parsed_uri.get('username'))
            host, port = self._parsed_uri.get('nodelist')[0]
            if port == '27017':
                hostport = host
            else:
                if ':' in host and not host.endswith(']'):
                    # IPv6 address without brackets
                    host = '[{!s}]'.format(host)
                hostport = '{!s}:{!s}'.format(host, port)

            self._sanitized_uri = 'mongodb://{userpass!s}{hostport!s}/{dbname!s}'.format(
                userpass = userpass,
                hostport = hostport,
                dbname = self._database_name,
                )
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
