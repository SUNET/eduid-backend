__author__ = 'leifj'

import time
import atexit
import shutil
import tempfile
import unittest
import subprocess
import os
import pymongo

MONGODB_TEST_PORT = 45456


class MongoTemporaryInstance(object):
    """Singleton to manage a temporary MongoDB instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.

    """
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            atexit.register(cls._instance.shutdown)
        return cls._instance

    def __init__(self):
        self._tmpdir = tempfile.mkdtemp()
        self._process = subprocess.Popen(['mongod', '--bind_ip', 'localhost',
                                          '--port', str(MONGODB_TEST_PORT),
                                          '--dbpath', self._tmpdir,
                                          '--nojournal', '--nohttpinterface',
                                          '--noauth', '--smallfiles',
                                          '--syncdelay', '0',
                                          '--maxConns', '10',
                                          '--nssize', '1', ],
                                         stdout=open(os.devnull, 'wb'),
                                         stderr=subprocess.STDOUT)

        # XXX: wait for the instance to be ready
        #      Mongo is ready in a glance, we just wait to be able to open a
        #      Connection.
        for i in range(3):
            time.sleep(0.1)
            try:
                self._conn = pymongo.Connection('localhost', MONGODB_TEST_PORT)
            except pymongo.errors.ConnectionFailure:
                continue
            else:
                break
        else:
            self.shutdown()
            assert False, 'Cannot connect to the mongodb test instance'

    @property
    def conn(self):
        return self._conn

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
            shutil.rmtree(self._tmpdir, ignore_errors=True)


class MongoTestCase(unittest.TestCase):
    """TestCase with an embedded MongoDB temporary instance.

    Each test runs on a temporary instance of MongoDB. Please note that
    these tests are not thread-safe and different processes should set a
    different value for the listening port of the MongoDB instance with the
    settings `MONGODB_TEST_PORT`.

    A test can access the connection using the attribute `conn`.

    """
    fixtures = []

    def __init__(self, *args, **kwargs):
        super(MongoTestCase, self).__init__(*args, **kwargs)
        self.db = MongoTemporaryInstance.get_instance()
        self.conn = self.db.conn

    def setUp(self):
        super(MongoTestCase, self).setUp()

        for db_name in self.conn.database_names():
            self.conn.drop_database(db_name)
