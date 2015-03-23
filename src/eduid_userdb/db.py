import pymongo


DEFAULT_MONGODB_HOST = 'localhost'
DEFAULT_MONGODB_PORT = 27017
DEFAULT_MONGODB_NAME = 'eduid_userdb'
DEFAULT_MONGODB_URI = 'mongodb://%s:%d/%s' % (DEFAULT_MONGODB_HOST,
                                              DEFAULT_MONGODB_PORT,
                                              DEFAULT_MONGODB_NAME)


class MongoDB(object):
    """Simple wrapper to get pymongo real objects from the settings uri"""

    def __init__(self, db_uri=DEFAULT_MONGODB_URI,
                 connection_factory=None, **kwargs):

        self.db_uri = db_uri

        if db_uri == "mongodb://":
            db_uri = DEFAULT_MONGODB_URI

        self.parsed_uri = pymongo.uri_parser.parse_uri(db_uri)

        _options = self.parsed_uri.get('options')
        if 'replicaSet' in kwargs or 'replicaSet' in _options:
            connection_factory = pymongo.MongoReplicaSetClient
        if 'replicaSet' in _options:
            connection_factory = pymongo.MongoReplicaSetClient
            kwargs['replicaSet'] = _options['replicaSet']

        elif connection_factory is None:
            connection_factory = pymongo.MongoClient

        self._connection = connection_factory(
            host=self.db_uri,
            tz_aware=True,
            **kwargs)

        if self.parsed_uri.get("database", None):
            self.database_name = self.parsed_uri["database"]
        else:
            self.database_name = DEFAULT_MONGODB_NAME

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

        :param database_name: (optional) Name of databas
        :param username: (optional) Username to login with
        :param password: (optional) Password to login with
        :return: Pymongo database object
        """
        if database_name is None:
            db = self._connection[self.database_name]
        else:
            db = self._connection[database_name]
        if username and password:
            db.authenticate(username, password)
        elif self.parsed_uri.get("username", None):
            db.authenticate(
                self.parsed_uri.get("username", None),
                self.parsed_uri.get("password", None)
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
