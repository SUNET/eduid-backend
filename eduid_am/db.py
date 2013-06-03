import urlparse

import pymongo


DEFAULT_MONGODB_HOST = 'localhost'
DEFAULT_MONGODB_PORT = 27017
DEFAULT_MONGODB_NAME = 'eduid_am'
DEFAULT_MONGODB_URI = 'mongodb://%s:%d/%s' % (DEFAULT_MONGODB_HOST,
                                              DEFAULT_MONGODB_PORT,
                                              DEFAULT_MONGODB_NAME)


class MongoDB(object):
    """Simple wrapper to get pymongo real objects from the settings uri"""

    def __init__(self, db_uri=DEFAULT_MONGODB_URI,
                 connection_factory=pymongo.Connection):
        self.db_uri = urlparse.urlparse(db_uri)
        self.connection = connection_factory(
            host=self.db_uri.hostname or DEFAULT_MONGODB_HOST,
            port=self.db_uri.port or DEFAULT_MONGODB_PORT,
            tz_aware=True)

    def get_connection(self):
        return self.connection

    def get_database(self, database_name, username=None, password=None, default_auth=False):
        database = self.connection[database_name]
        if not username and not password and default_auth:
            username = self.db_uri.username
            password = self.db_uri.password
        if username and password:
            database.authenticate(username, password)

        return database
