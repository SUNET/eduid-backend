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
from __future__ import annotations

import atexit
import json
import logging
import random
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
import warnings
from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional, Sequence, Type
from typing import Dict, List, Mapping, Union

import pymongo

from eduid_userdb import User, UserDB
from eduid_userdb.dashboard.user import DashboardUser
from eduid_userdb.fixtures.users import mocked_user_standard, mocked_user_standard_2
from eduid_userdb.util import utc_now

logger = logging.getLogger(__name__)


MONGO_URI_AM_TEST = 'mongodb://localhost:27017/eduid_userdb_test'
MONGO_URI_TEST = 'mongodb://localhost:27017/eduid_dashboard_test'

# eduid_userdb.db.DEFAULT_MONGODB_URI = MONGO_URI_AM_TEST
# eduid_userdb.db.DEFAULT_MONGODB_NAME = 'eduid_userdb_test'


# Also used in the APIMockedUserDB at eduid_common.api.testing
class AbstractMockedUserDB(ABC):
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


class MockedUserDB(AbstractMockedUserDB, UserDB):
    """
    Some mock users used in different tests.

    Need to do deepcopy everywhere to better isolate tests from each other - since this is
    an in-memory database, one test might manipulate the returned data and could otherwise
    potentially affect other tests using the same data.
    """

    test_users = {
        'johnsmith@example.com': mocked_user_standard.to_dict(),
        'johnsmith@example.org': mocked_user_standard_2.to_dict(),
    }

    def __init__(self, users=[]):
        import pprint

        for user in users:
            mail = user.get('mail', '')
            if mail in self.test_users:
                logger.debug("Updating MockedUser {!r} with:\n{!s}".format(mail, pprint.pformat(user)))
                self.test_users[mail].update(user)
                logger.debug("New MockedUser {!r}:\n{!s}".format(mail, pprint.pformat(self.test_users[mail])))


class EduidTemporaryInstance(ABC):
    """Singleton to manage a temporary instance of something needed when testing.

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """

    _instance = None

    def __init__(self, max_retry_seconds: int):
        self._conn: Optional[Any] = None  # self._conn should be initialised by subclasses in `setup_conn'
        self._tmpdir = tempfile.mkdtemp()
        self._port = random.randint(40000, 65535)
        self._logfile = f'/tmp/{self.__class__.__name__}-{self.port}.log'

        start_time = utc_now()
        self._process = subprocess.Popen(self.command, stdout=open(self._logfile, 'wb'), stderr=subprocess.STDOUT,)

        interval = 0.2
        count = 0
        while True:
            count += 1
            time.sleep(interval)

            # Call a function of the subclass of this ABC to see if the instance is operational yet
            _res = self.setup_conn()

            time_now = utc_now()
            delta = time_now - start_time
            age = delta.total_seconds()
            if _res:
                logger.info(f'{self} instance started after {age} seconds (attempt {count})')
                break
            if age > max_retry_seconds:
                logger.error(f'{self} instance failed to start after {age} seconds')
                logger.error(f'{self} instance output:\n{self.output}')
                raise RuntimeError(f'{self} instance failed to start after {age} seconds')

    @classmethod
    def get_instance(cls: Type[EduidTemporaryInstance], max_retry_seconds: int = 20) -> EduidTemporaryInstance:
        """
        Start a new temporary instance, or retrieve an already started one.

        :param max_retry_seconds: Time allowed for the instance to start
        :return:
        """
        if cls._instance is None:
            cls._instance = cls(max_retry_seconds=max_retry_seconds)
            atexit.register(cls._instance.shutdown)
        return cls._instance

    @abstractmethod
    def setup_conn(self) -> bool:
        """
        Initialise and test a connection of the instance in self._conn.

        Return True on success.
        """
        raise NotImplemented('All subclasses of EduidTemporaryInstance must implement setup_conn')

    @property
    @abstractmethod
    def conn(self) -> Any:
        """ Return the initialised _conn instance. No default since it ought to be typed in the subclasses. """
        raise NotImplemented('All subclasses of EduidTemporaryInstance should implement the conn property')

    @property
    @abstractmethod
    def command(self) -> Sequence[str]:
        """ This is the shell command to start the temporary instance. """
        raise NotImplemented('All subclasses of EduidTemporaryInstance must implement the command property')

    @property
    def port(self) -> int:
        return self._port

    @property
    def tmpdir(self) -> str:
        return self._tmpdir

    @property
    def output(self) -> str:
        with open(self._logfile, 'r') as fd:
            _output = ''.join(fd.readlines())
        return _output

    def shutdown(self):
        logger.debug(f'{self} output at shutdown:\n{self.output}')
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
        shutil.rmtree(self._tmpdir, ignore_errors=True)


class MongoTemporaryInstance(EduidTemporaryInstance):
    """Singleton to manage a temporary MongoDB instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """
    @property
    def command(self) -> Sequence[str]:
        return ['docker', 'run', '--rm', '-p', '{!s}:27017'.format(self._port), 'docker.sunet.se/eduid/mongodb:latest']

    def setup_conn(self) -> bool:
        try:
            self._conn = pymongo.MongoClient('localhost', self._port)
            logger.info('Connected to temporary mongodb instance: {}'.format(self._conn))
        except pymongo.errors.ConnectionFailure:
            return False
        return True

    @property
    def conn(self) -> pymongo.MongoClient:
        if self._conn is None:
            raise RuntimeError('Missing temporary MongoDB instance')
        return self._conn

    @property
    def uri(self):
        return 'mongodb://localhost:{}'.format(self.port)

    def shutdown(self):
        if self._conn:
            logger.info('Closing connection {}'.format(self._conn))
            self._conn.close()
            self._conn = None
        super().shutdown()


class SortEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return str(_normalise_value(obj))
        if isinstance(obj, Enum):
            return _normalise_value(obj)
        if isinstance(obj, uuid.UUID):
            return str(obj)
        return json.JSONEncoder.default(self, obj)


def _any_key(value: Any):
    """ Helper function to be able to use sorted with key argument for everything """
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, cls=SortEncoder)  # Turn dict in to a string for sorting
    return value


def _normalise_value(data: Any) -> Any:
    if isinstance(data, dict) or isinstance(data, list):
        return normalised_data(data)
    elif isinstance(data, datetime):
        # Check if datetime is timezone aware
        if data.tzinfo is not None and data.tzinfo.utcoffset(data) is not None:
            # Raise an exception if the timezone is not equivalent to UTC
            if data.tzinfo.utcoffset(data) != timedelta(seconds=0):
                raise ValueError(f'Non UTC timezone found: {data.tzinfo}')
        else:
            # TODO: Naive datetimes should maybe generate a warning?
            pass
        # Make sure all datetimes has the same type of tzinfo object
        data = data.replace(tzinfo=timezone.utc)
        return data.replace(microsecond=0)
    if isinstance(data, Enum):
        return f'{repr(data)}'
    return data


def normalised_data(
    data: Union[Mapping[str, Any], Sequence[Mapping[str, Any]]]
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """ Utility function for normalising dicts (or list of dicts) before comparisons in test cases. """
    if isinstance(data, list):
        # Recurse into lists of dicts. mypy (correctly) says this recursion can in fact happen
        # more than once, so the result can be a list of list of dicts or whatever, but the return
        # type becomes too bloated with that in mind and the code becomes too inelegant when unrolling
        # this list comprehension into a for-loop checking types for something only intended to be used in test cases.
        # Hence the type: ignore.
        return sorted([_normalise_value(x) for x in data], key=_any_key)  # type: ignore
    elif isinstance(data, dict):
        # normalise all values found in the dict, returning a new dict (to not modify callers data)
        return {k: _normalise_value(v) for k, v in data.items()}
    raise TypeError('normalised_data not called on dict (or list of dicts)')


class DictTestCase(unittest.TestCase):
    """
    """

    maxDiff = None
    warnings.warn(
        'DictTestCase deprecated - use testing.normalised_data instead', category=DeprecationWarning, stacklevel=2
    )

    @classmethod
    def normalize_users(cls, users: List[Dict[str, Any]]):
        """
        Remove timestamps that in general are created at different times
        normalize the names of some attributes
        """
        for user in users:
            cls.normalize_elem(user)

            if 'mailAliases' in user:
                cls.normalize_data(user['mailAliases'], [])

            if 'passwords' in user:
                cls.normalize_data(user['passwords'], [])

            if 'phone' in user:
                cls.normalize_data(user['phone'], [])

            if 'profiles' in user:
                cls.normalize_data(user['profiles'], [])

            if 'nins' in user:
                cls.normalize_data(user['nins'], [])

    @classmethod
    def normalize_data(cls, expected: List[Dict[str, Any]], obtained: List[Dict[str, Any]]):
        """
        Remove timestamps that in general are created at different times
        normalize the names of some attributes
        remove attributes set to None
        """
        for elist in (expected, obtained):
            for elem in elist:
                cls.normalize_elem(elem)

    @classmethod
    def normalize_elem(cls, elem: Dict[str, Any]):
        if 'created_ts' in elem:
            assert isinstance(elem['created_ts'], datetime)
            del elem['created_ts']

        if 'modified_ts' in elem:
            if elem['modified_ts'] is not None:
                assert isinstance(elem['modified_ts'], datetime)
            del elem['modified_ts']

        if 'verified_ts' in elem:
            if elem['verified_ts'] is not None:
                assert isinstance(elem['verified_ts'], datetime)
            del elem['verified_ts']

        if 'terminated' in elem:
            if elem['terminated'] is not None:
                assert isinstance(elem['terminated'], datetime)
            del elem['terminated']

        if 'application' in elem:
            elem['created_by'] = elem.pop('application')

        if 'source' in elem:
            elem['created_by'] = elem.pop('source')

        if 'credential_id' in elem:
            elem['id'] = elem.pop('credential_id')

        for key in elem:
            if isinstance(elem[key], dict):
                cls.normalize_elem(elem[key])


class MongoTestCase(DictTestCase):
    """TestCase with an embedded MongoDB temporary instance.

    Each test runs on a temporary instance of MongoDB. The instance will
    be listen in a random port between 40000 and 50000.

    A test can access the connection using the attribute `conn`.
    A test can access the port using the attribute `port`
    """

    fixtures: list = []

    MockedUserDB: Type[AbstractMockedUserDB] = MockedUserDB

    user = User.from_dict(mocked_user_standard.to_dict())
    mock_users_patches: list = []

    def setUp(self, init_am=False, am_settings=None):
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

        :param init_am: True if the test needs am
        :param am_settings: Test specific am settings
        :return:
        """
        super(MongoTestCase, self).setUp()
        self.tmp_db = MongoTemporaryInstance.get_instance()

        if init_am:
            self.am_settings = {
                'CELERY': {
                    'broker_transport': 'memory',
                    'broker_url': 'memory://',
                    'task_eager_propagates': True,
                    'task_always_eager': True,
                    'result_backend': 'cache',
                    'cache_backend': 'memory',
                },
                # Be sure to NOT tell AttributeManager about the temporary mongodb instance.
                # If we do, one or more plugins may open DB connections that never gets closed.
                'MONGO_URI': None,
            }

            if am_settings:
                want_mongo_uri = am_settings.pop('WANT_MONGO_URI', False)
                self.am_settings.update(am_settings)
                if want_mongo_uri:
                    self.am_settings['MONGO_URI'] = self.tmp_db.uri
            # initialize eduid_am without requiring config in etcd
            import eduid_am

            celery = eduid_am.init_app(self.am_settings['CELERY'])
            import eduid_am.worker

            eduid_am.worker.worker_config = self.am_settings
            logger.debug('Initialized AM with config:\n{!r}'.format(self.am_settings))

            self.am = eduid_am.get_attribute_manager(celery)
        self.amdb = UserDB(self.tmp_db.uri, 'eduid_am')

        mongo_settings = {
            'mongo_replicaset': None,
            'mongo_uri': self.tmp_db.uri,
        }

        if getattr(self, 'settings', None) is None:
            self.settings = mongo_settings
        else:
            self.settings.update(mongo_settings)

        # Set up test users in the MongoDB. Read the users from MockedUserDB, which might
        # be overridden by subclasses.
        _foo_userdb = self.MockedUserDB(self.mock_users_patches)
        for userdoc in _foo_userdb.all_userdocs():
            this = deepcopy(userdoc)  # deep-copy to not have side effects between tests
            user = User.from_dict(data=this)
            self.amdb.save(user, check_sync=False, old_format=False)

    def tearDown(self):
        for userdoc in self.amdb._get_all_docs():
            assert DashboardUser.from_dict(data=userdoc)
        # Reset databases for the next test class, but do not shut down the temporary
        # mongodb instance, for efficiency reasons.
        for db_name in self.tmp_db.conn.list_database_names():
            if db_name not in ['local', 'admin', 'config']:  # Do not drop mongo internal dbs
                self.tmp_db.conn.drop_database(db_name)
        self.amdb._drop_whole_collection()
        self.amdb.close()
        super(MongoTestCase, self).tearDown()

    # def mongodb_uri(self, dbname):
    #    self.assertIsNotNone(dbname)
    #    return self.tmp_db.uri + '/' + dbname
