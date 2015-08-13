#
# Copyright (c) 2013, 2014, 2015 NORDUnet A/S
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

"""
Code used in unit tests of various eduID applications.
"""

__author__ = 'leifj'

import time
import atexit
import random
import tempfile
import unittest
import subprocess
import pymongo
from datetime import datetime
from copy import deepcopy

from bson import ObjectId

from eduid_userdb import UserDB, User
from eduid_userdb.data_samples import NEW_BASIC_USER_EXAMPLE

import logging
logger = logging.getLogger(__name__)


def get_two_test_users():
    first_user = deepcopy(NEW_BASIC_USER_EXAMPLE)
    second_user = deepcopy(NEW_BASIC_USER_EXAMPLE)
    second_user['_id'] = ObjectId('901234567890123456789012')
    second_user['mail'] = 'johnsmith@example.org'
    second_user['eduPersonPrincipalName'] = 'babba-labba'
    second_user['mailAliases'][0]['email'] = 'johnsmith@example.org'
    second_user['mailAliases'][1]['email'] = 'johnsmith2@example.org'
    second_user['nins'][0]['number'] = '196701101234'
    second_user['phone'] = []
    return first_user, second_user


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
        self._port = random.randint(40000, 50000)
        self._process = subprocess.Popen(['mongod', '--bind_ip', 'localhost',
                                          '--port', str(self._port),
                                          '--dbpath', self._tmpdir,
                                          '--nojournal', '--nohttpinterface',
                                          '--noauth', '--smallfiles',
                                          '--syncdelay', '0',
                                          '--nssize', '1', ],
                                         stdout=open('/tmp/mongo-temp.log', 'wb'),
                                         stderr=subprocess.STDOUT)

        # XXX: wait for the instance to be ready
        #      Mongo is ready in a glance, we just wait to be able to open a
        #      Connection.
        for i in range(10):
            time.sleep(0.2)
            try:
                self._conn = pymongo.Connection('localhost', self._port)
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

    @property
    def port(self):
        return self._port

    def shutdown(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
            #shutil.rmtree(self._tmpdir, ignore_errors=True)

    def get_uri(self, dbname=''):
        """
        Convenience function to get a mongodb URI to the temporary database.

        :param dbname: database name
        :return: URI
        """
        return 'mongodb://localhost:{port!s}/{dbname!s}'.format(port=self.port, dbname=dbname)


class MongoTestCase(unittest.TestCase):
    """TestCase with an embedded MongoDB temporary instance.

    Each test runs on a temporary instance of MongoDB. The instance will
    be listen in a random port between 40000 and 5000.

    A test can access the connection using the attribute `conn`.
    A test can access the port using the attribute `port`
    """

    def setUp(self):
        """
        Test case initialization.

        :return:
        """
        super(MongoTestCase, self).setUp()
        self.tmp_db = MongoTemporaryInstance.get_instance()
        self.conn = self.tmp_db.conn
        self.port = self.tmp_db.port

        mongo_settings = {
            'mongo_replicaset': None,
            'mongo_uri_am': self.tmp_db.get_uri('eduid_userdb'),
        }

        if getattr(self, 'settings', None) is None:
            self.settings = mongo_settings
        else:
            self.settings.update(mongo_settings)

        for db_name in self.conn.database_names():
            self.conn.drop_database(db_name)

    def mongodb_uri(self, dbname=None):
        return self.tmp_db.get_uri(dbname=dbname)
