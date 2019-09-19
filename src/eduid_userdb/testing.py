#
# Copyright (c) 2013, 2014, 2015 NORDUnet A/S
# Copyright (c) 2018 SUNET
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

import atexit
import logging
import random
import subprocess
import time
import unittest
from copy import deepcopy

import pymongo
from bson import ObjectId

from eduid_userdb import UserDB, User
from eduid_userdb.dashboard.user import DashboardUser

logger = logging.getLogger(__name__)


MONGO_URI_AM_TEST = 'mongodb://localhost:27017/eduid_userdb_test'
MONGO_URI_TEST = 'mongodb://localhost:27017/eduid_dashboard_test'

#eduid_userdb.db.DEFAULT_MONGODB_URI = MONGO_URI_AM_TEST
#eduid_userdb.db.DEFAULT_MONGODB_NAME = 'eduid_userdb_test'


MOCKED_USER_STANDARD = {
    '_id': ObjectId('012345678901234567890123'),
    'givenName': 'John',
    'surname': 'Smith',
    'displayName': 'John Smith',
    'norEduPersonNIN': [{'number': '197801011234',
                         'verified': True,
                         'primary': True,
                         }],
    #'photo': 'https://pointing.to/your/photo',
    'preferredLanguage': 'en',
    'eduPersonPrincipalName': 'hubba-bubba',
    #'modified_ts': datetime.strptime("2013-09-02T10:23:25", "%Y-%m-%dT%H:%M:%S"),
    #'terminated': None,
    'eduPersonEntitlement': [
        'urn:mace:eduid.se:role:admin',
        'urn:mace:eduid.se:role:student',
    ],
    'phone': [{
        'number': '+34609609609',
        'primary': True,
        'verified': True
    }, {
        'number': '+34 6096096096',
        'verified': False
    }, {
        'number': '+34607507507',
        'verified': True
    }],
    'mail': 'johnsmith@example.com',
    'mailAliases': [{
        'email': 'johnsmith@example.com',
        'verified': True,
    }, {
        'email': 'johnsmith2@example.com',
        'verified': True,
    }, {
        'email': 'johnsmith3@example.com',
        'verified': False,
    }],
    'passwords': [{
        'id': ObjectId('112345678901234567890123'),
        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
    }],
    #'postalAddress': [{
    #    'type': 'home',
    #    'country': 'SE',
    #    'address': "Long street, 48",
    #    'postalCode': "123456",
    #    'locality': "Stockholm",
    #    'verified': True,
    #}, {
    #    'type': 'work',
    #    'country': 'ES',
    #    'address': "Calle Ancha, 49",
    #    'postalCode': "123456",
    #    'locality': "Punta Umbria",
    #    'verified': False,
    #}],
}

class MockedUserDB(UserDB):
    """
    Some mock users used in different tests.

    Need to do deepcopy everywhere to better isolate tests from each other - since this is
    an in-memory database, one test might manipulate the returned data and could otherwise
    potentially affect other tests using the same data.
    """

    test_users = {
        'johnsmith@example.com': deepcopy(MOCKED_USER_STANDARD),
        'johnsmith@example.org': deepcopy(MOCKED_USER_STANDARD),
    }
    test_users['johnsmith@example.org']['mail'] = 'johnsmith@example.org'
    test_users['johnsmith@example.org']['mailAliases'][0]['email'] = 'johnsmith@example.org'
    test_users['johnsmith@example.org']['mailAliases'][1]['email'] = 'johnsmith2@example.org'
    test_users['johnsmith@example.org']['_id'] = ObjectId('901234567890123456789012')
    test_users['johnsmith@example.org']['norEduPersonNIN'] = []
    test_users['johnsmith@example.org']['phone'] = []
    test_users['johnsmith@example.org']['eduPersonPrincipalName'] = 'babba-labba'

    def __init__(self, users=[]):
        import pprint
        for user in users:
            mail = user.get('mail', '')
            if mail in self.test_users:
                logger.debug("Updating MockedUser {!r} with:\n{!s}".format(mail, pprint.pformat(user)))
                self.test_users[mail].update(user)
                logger.debug("New MockedUser {!r}:\n{!s}".format(mail, pprint.pformat(self.test_users[mail])))

    def get_user(self, userid):
        if userid not in self.test_users:
            raise self.UserDoesNotExist
        return User(deepcopy(self.test_users.get(userid)))

    def all_users(self):
        for user in self.test_users.values():
            yield User(deepcopy(user))

    def all_userdocs(self):
        for user in self.test_users.values():
            yield deepcopy(user)


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
        self._port = random.randint(40000, 50000)
        logger.debug('Starting temporary mongodb instance on port {}'.format(self._port))
        self._process = subprocess.Popen(['docker', 'run', '--rm',
                                          '-p', '{!s}:27017'.format(self._port),
                                          'docker.sunet.se/eduid/mongodb:latest',
                                          ],
                                         stdout=open('/tmp/mongodb-temp.log', 'wb'),
                                         stderr=subprocess.STDOUT)
        # XXX: wait for the instance to be ready
        #      Mongo is ready in a glance, we just wait to be able to open a
        #      Connection.
        for i in range(100):
            time.sleep(0.2)
            try:
                self._conn = pymongo.MongoClient('localhost', self._port)
                logger.info('Connected to temporary mongodb instance: {}'.format(self._conn))
            except pymongo.errors.ConnectionFailure:
                logger.debug('Connect failed ({})'.format(i))
                continue
            else:
                if self._conn is not None:
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

    @property
    def uri(self):
        return 'mongodb://localhost:{}'.format(self.port)

    def close(self):
        if self._conn:
            logger.info('Closing connection {}'.format(self._conn))
            self._conn.close()
            self._conn = None

    def shutdown(self):
        if self._process:
            self.close()
            logger.info('Shutting down {}'.format(self))
            self._process.terminate()
            self._process.wait()
            self._process = None


class MongoTestCase(unittest.TestCase):
    """TestCase with an embedded MongoDB temporary instance.

    Each test runs on a temporary instance of MongoDB. The instance will
    be listen in a random port between 40000 and 50000.

    A test can access the connection using the attribute `conn`.
    A test can access the port using the attribute `port`
    """
    fixtures = []

    MockedUserDB = MockedUserDB

    user = User(data=MOCKED_USER_STANDARD)
    mock_users_patches = []

    def setUp(self):
        """
        Test case initialization.

        To not get a circular dependency between eduid-userdb and eduid-am, celery
        and get_attribute_manager needs to be imported in the place where this
        module is called.

        Usage:

            from eduid_am.celery import celery, get_attribute_manager

            class MyTest(MongoTestCase):

                def setUp(self):
                    super(MyTest, self).setUp(celery, get_attribute_manager)
                    ...
        """
        super(MongoTestCase, self).setUp()
        self.tmp_db = MongoTemporaryInstance.get_instance()

        self.amdb = UserDB(self.tmp_db.uri, 'eduid_am')

        # Set up test users in the MongoDB. Read the users from MockedUserDB, which might
        # be overridden by subclasses.
        _foo_userdb = self.MockedUserDB(self.mock_users_patches)
        for userdoc in _foo_userdb.all_userdocs():
            this = deepcopy(userdoc)  # deep-copy to not have side effects between tests
            user = User(data=this)
            self.amdb.save(user, check_sync=False)

    def tearDown(self):
        for userdoc in self.amdb._get_all_docs():
            assert DashboardUser(data=userdoc)
        # Reset databases for the next test class, but do not shut down the temporary
        # mongodb instance, for efficiency reasons.
        for db_name in self.tmp_db.conn.list_database_names():
            if db_name not in ['local', 'admin', 'config']:  # Do not drop mongo internal dbs
                self.tmp_db.conn.drop_database(db_name)
        self.amdb._drop_whole_collection()
        self.amdb.close()
        super(MongoTestCase, self).tearDown()
