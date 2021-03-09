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

import json
import logging
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

import pymongo

from eduid.userdb import User, UserDB
from eduid.userdb.dashboard.user import DashboardUser
from eduid.userdb.testing.temp_instance import EduidTemporaryInstance

logger = logging.getLogger(__name__)


class MongoTemporaryInstance(EduidTemporaryInstance):
    """Singleton to manage a temporary MongoDB instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """

    @property
    def command(self) -> Sequence[str]:
        return ['docker', 'run', '--rm', '-p', f'{self._port!s}:27017', 'docker.sunet.se/eduid/mongodb:latest']

    def setup_conn(self) -> bool:
        try:
            self._conn = pymongo.MongoClient('localhost', self._port)
            logger.info(f'Connected to temporary mongodb instance: {self._conn}')
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
        return f'mongodb://localhost:{self.port}'

    def shutdown(self):
        if self._conn:
            logger.info(f'Closing connection {self._conn}')
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


class MongoTestCase(unittest.TestCase):
    """TestCase with an embedded MongoDB temporary instance.

    Each test runs on a temporary instance of MongoDB. The instance will
    be listen in a random port between 40000 and 50000.

    A test can access the connection using the attribute `conn`.
    A test can access the port using the attribute `port`
    """

    def setUp(self, am_users: Optional[List[User]] = None, **kwargs):
        """
        Test case initialization.

        To not get a circular dependency between eduid-userdb and eduid-am, celery
        and get_attribute_manager needs to be imported in the place where this
        module is called.

        Usage:

            from eduid.workers.am.celery import celery, get_attribute_manager

            class MyTest(MongoTestCase):

                def setUp(self):
                    super(MyTest, self).setUp(celery, get_attribute_manager)
                    ...

        :param init_am: True if the test needs am
        :param am_settings: Test specific am settings
        :return:
        """
        super().setUp()
        self.tmp_db = MongoTemporaryInstance.get_instance()
        assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy
        self.amdb = UserDB(self.tmp_db.uri, 'eduid_am')

        mongo_settings = {
            'mongo_replicaset': None,
            'mongo_uri': self.tmp_db.uri,
        }

        if getattr(self, 'settings', None) is None:
            self.settings = mongo_settings
        else:
            self.settings.update(mongo_settings)

        if am_users:
            # Set up test users in the MongoDB.
            for user in am_users:
                self.amdb.save(user, check_sync=False)

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
        super().tearDown()
