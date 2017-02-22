#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import os
import unittest
import time
import atexit
import random
import subprocess
from contextlib import contextmanager
from copy import deepcopy

import redis
import etcd

from eduid_userdb import User
from eduid_userdb.data_samples import NEW_USER_EXAMPLE
from eduid_userdb.testing import MongoTemporaryInstance


TEST_CONFIG = {
    'DEBUG': 'True',
    'TESTING': 'True',
    'SECRET_KEY': 'mysecretkey',
    'SESSION_COOKIE_NAME': 'sessid',
    'SESSION_COOKIE_DOMAIN': 'test.localhost',
    'SESSION_COOKIE_PATH': '/',
    'SESSION_COOKIE_HTTPONLY': 'False',
    'SESSION_COOKIE_SECURE': 'False',
    'PERMANENT_SESSION_LIFETIME': '60',
    'LOGGER_NAME': 'testing',
    'SERVER_NAME': 'test.localhost',
    'PROPAGATE_EXCEPTIONS': 'True',
    'PRESERVE_CONTEXT_ON_EXCEPTION': 'True',
    'TRAP_HTTP_EXCEPTIONS': 'True',
    'TRAP_BAD_REQUEST_ERRORS': 'True',
    'PREFERRED_URL_SCHEME': 'http',
    'JSON_AS_ASCII': 'False',
    'JSON_SORT_KEYS': 'True',
    'JSONIFY_PRETTYPRINT_REGULAR': 'True',
    'MONGO_URI': 'mongodb://dummy',
    'REDIS_HOST': 'localhost',
    'REDIS_PORT': '6379',
    'REDIS_DB': '0',
    'REDIS_SENTINEL_HOSTS': '',
    'REDIS_SENTINEL_SERVICE_NAME': '',
    'TOKEN_SERVICE_URL': 'http://test.localhost/',
}


class EduidAPITestCase(unittest.TestCase):
    """
    Base Test case for eduID APIs.

    See the `load_app` and `update_config` methods below before subclassing.
    """

    def setUp(self):
        self.redis_instance = RedisTemporaryInstance.get_instance()
        self.mongo_instance = MongoTemporaryInstance.get_instance()
        self.etcd_instance = EtcdTemporaryInstance.get_instance()
        config = deepcopy(TEST_CONFIG)
        config = self.update_config(config)
        config['REDIS_PORT'] = str(self.redis_instance.port)
        config['MONGO_URI'] = 'mongodb://localhost:{}/'.format(self.mongo_instance.port)
        os.environ.update({'ETCD_PORT': str(self.etcd_instance.port)})
        self.app = self.load_app(config)
        self.browser = self.app.test_client()
        self.test_user_data = deepcopy(NEW_USER_EXAMPLE)
        self.test_user = User(data=self.test_user_data)
        with self.app.app_context():
            self.app.central_userdb.save(self.test_user, check_sync=False)
            self.init_data()

        # Helper constants
        self.content_type_json = 'application/json'

    def tearDown(self):
        # XXX reset redis
        pass

    def load_app(self, config):
        """
        Method that must be implemented by any subclass, where the
        flask app must be imported and returned.
        This is so we can set  the test configuration in environment variables
        before the flask app loads its config from a file.
        """
        msg = ('Classes extending EduidAPITestCase must provide a method '
               'where they import the flask app and return it.')
        raise NotImplementedError(msg)

    def update_config(self, config):
        """
        Method that can be overriden by any subclass,
        where it can add configuration specific for that API
        before loading the app.

        :param config: original configuration
        :type config: dict

        :return: the updated configuration
        :rtype: dict
        """
        return config

    def init_data(self):
        """
        Method that can be overriden by any subclass,
        where it can add application specific data to the test dbs
        """
        pass

    @contextmanager
    def session_cookie(self, client, eppn, server_name='localhost'):
        with client.session_transaction() as sess:
            sess['user_eppn'] = eppn
            sess.persist()
        client.set_cookie(server_name, key=self.app.config.get('SESSION_COOKIE_NAME'), value=sess._session.token)
        yield client


class RedisTemporaryInstance(object):
    """Singleton to manage a temporary Redis instance

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
        self._port = random.randint(40000, 50000)
        self._process = subprocess.Popen(['redis-server',
                                          '--port', str(self._port),
                                          '--daemonize', 'no',
                                          '--bind', '0.0.0.0',
                                          '--databases', '1',],
                                         stdout=open('/tmp/redis-temp.log', 'wb'),
                                         stderr=subprocess.STDOUT)

        for i in range(10):
            time.sleep(0.2)
            try:
                self._conn = redis.Redis('localhost', self._port, 0)
                self._conn.set('dummy', 'dummy')
            except redis.exceptions.ConnectionError:
                continue
            else:
                break
        else:
            self.shutdown()
            assert False, 'Cannot connect to the redis test instance'

    @property
    def conn(self):
        return self._conn

    @property
    def port(self):
        return self._port

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None

    def get_uri(self):
        """
        Convenience function to get a redis URI to the temporary database.

        :return: host, port, dbname
        """
        return 'localhost', self.port, 0


class EtcdTemporaryInstance(object):
    """Singleton to manage a temporary Etcd instance

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
        self._port = random.randint(40000, 50000)
        self._process = subprocess.Popen(['docker', 'run', '--rm',
                                          '-p', '{!s}:2379'.format(self._port),
                                          'docker.sunet.se/library/etcd:v2.2.5',
                                          '-advertise-client-urls', 'http://${HostIP}:2379',
                                          '-listen-client-urls', 'http://0.0.0.0:2379'],
                                         stdout=open('/tmp/etcd-temp.log', 'wb'),
                                         stderr=subprocess.STDOUT)

        for i in range(10):
            time.sleep(0.2)
            try:
                self._conn = etcd.Client('localhost', self._port)
                self._conn.stats  # Check connection
            except etcd.EtcdConnectionFailed:
                continue
            else:
                break
        else:
            self.shutdown()
            assert False, 'Cannot connect to the etcd test instance'

    @property
    def conn(self):
        return self._conn

    @property
    def host(self):
        return self._conn.host

    @property
    def port(self):
        return self._port

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
