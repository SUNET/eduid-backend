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

import logging
import logging.config
import unittest
from typing import List, Optional, Sequence, Type, cast

import pymongo
import pymongo.errors

from eduid.common.logging import LocalContext, make_dictConfig
from eduid.userdb import User
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.testing.temp_instance import EduidTemporaryInstance
from eduid.userdb.userdb import AmDB

logger = logging.getLogger(__name__)


class MongoTemporaryInstance(EduidTemporaryInstance):
    """Singleton to manage a temporary MongoDB instance

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """

    @property
    def command(self) -> Sequence[str]:
        return [
            "docker",
            "run",
            "--rm",
            "-p",
            f"{self.port}:27017",
            "--name",
            f"test_mongodb_{self.port}",
            "docker.sunet.se/eduid/mongodb:latest",
        ]

    def setup_conn(self) -> bool:
        try:
            self._conn = pymongo.MongoClient("localhost", self._port)
            logger.info(f"Connected to temporary mongodb instance: {self._conn}")
        except pymongo.errors.ConnectionFailure:
            return False
        return True

    @property
    def conn(self) -> pymongo.MongoClient[TUserDbDocument]:
        if self._conn is None:
            raise RuntimeError("Missing temporary MongoDB instance")
        return self._conn

    @property
    def uri(self):
        return f"mongodb://localhost:{self.port}"

    def shutdown(self):
        if self._conn:
            logger.info(f"Closing connection {self._conn}")
            self._conn.close()
            self._conn = None
        super().shutdown()

    @classmethod
    def get_instance(cls: Type[MongoTemporaryInstance], max_retry_seconds: int = 20) -> MongoTemporaryInstance:
        return cast(MongoTemporaryInstance, super().get_instance(max_retry_seconds=max_retry_seconds))


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
        :return:
        """
        super().setUp()
        self.maxDiff = None

        # Set up provisional logging to capture logs from test setup too
        self._init_logging()

        self.tmp_db = MongoTemporaryInstance.get_instance()
        assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy
        self.amdb = AmDB(self.tmp_db.uri)

        logger.info("Resetting all databases for new tests")
        self._reset_databases()

        mongo_settings = {
            "mongo_replicaset": None,
            "mongo_uri": self.tmp_db.uri,
        }

        if getattr(self, "settings", None) is None:
            self.settings = mongo_settings
        else:
            self.settings.update(mongo_settings)

        if am_users:
            # Set up test users in the MongoDB.
            for user in am_users:
                logger.debug(f"Adding test user {user} to the database")
                self.amdb.save(user)

    def _init_logging(self):
        local_context = LocalContext(
            app_debug=True,
            app_name="testing",
            format="{asctime} | {levelname:7} |             | {name:35} | {message}",
            level="DEBUG",
            relative_time=True,
        )
        logging_config = make_dictConfig(local_context)
        logging.config.dictConfig(logging_config)

    def _reset_databases(self):
        """
        Reset databases for the next test class.

        We do this both at shutdown (to clean up) and in setUp() to make sure that tests get a clean environment.
        Particularly vscode doesn't always run tearDown(), when tests fails or the debugger is stopped mid-test.
        """
        for db_name in self.tmp_db.conn.list_database_names():
            if db_name not in ["local", "admin", "config"]:  # Do not drop mongo internal dbs
                self.tmp_db.conn.drop_database(db_name)
        self.amdb._drop_whole_collection()

    def tearDown(self):
        for userdoc in self.amdb._get_all_docs():
            assert User.from_dict(data=userdoc)
        self._reset_databases()
        # Close, but do not shut down the temporary MongoDB instance for performance reasons.
        self.amdb.close()
        super().tearDown()
