"""
Code used in unit tests of various eduID applications.
"""

from __future__ import annotations

import logging
import logging.config
import unittest
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Self, cast

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
    def uri(self) -> str:
        return f"mongodb://localhost:{self.port}"

    def shutdown(self) -> None:
        if self._conn:
            # close connection without logging as logging handlers may have been closed
            self._conn.close()
            self._conn = None
        super().shutdown()


@dataclass
class SetupConfig:
    am_users: list[User] | None = None
    am_settings: dict[str, Any] | None = None
    want_mongo_uri: bool = True
    users: list[str] | None = None
    copy_user_to_private: bool = False
    init_msg: bool = True
    init_lookup_mobile: bool = True


class MongoTestCase(unittest.TestCase):
    """TestCase with an embedded MongoDB temporary instance.

    Each test runs on a temporary instance of MongoDB. The instance will
    be listen in a random port between 40000 and 50000.

    A test can access the connection using the attribute `conn`.
    A test can access the port using the attribute `port`
    """

    def setUp(self, config: SetupConfig | None = None) -> None:
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

        if config is None:
            config = SetupConfig()
        if config.am_users:
            # Set up test users in the MongoDB.
            for user in config.am_users:
                logger.debug(f"Adding test user {user} to the database")
                self.amdb.save(user)

    def _init_logging(self) -> None:
        # Only initialize logging once to avoid creating multiple handlers
        # that reference pytest's captured streams which get closed during test execution
        if logging.getLogger().handlers:
            return
        local_context = LocalContext(
            app_debug=True,
            app_name="testing",
            format="{asctime} | {levelname:7} |             | {name:35} | {message}",
            level="DEBUG",
            relative_time=True,
        )
        logging_config = make_dictConfig(local_context)
        logging.config.dictConfig(logging_config)

    def _reset_databases(self) -> None:
        """
        Reset databases for the next test class.

        We do this both at shutdown (to clean up) and in setUp() to make sure that tests get a clean environment.
        Particularly vscode doesn't always run tearDown(), when tests fails or the debugger is stopped mid-test.
        """
        for db_name in self.tmp_db.conn.list_database_names():
            if db_name not in ["local", "admin", "config"]:  # Do not drop mongo internal dbs
                self.tmp_db.conn.drop_database(db_name)
        self.amdb._drop_whole_collection()

    def tearDown(self) -> None:
        for userdoc in self.amdb._get_all_docs():
            assert User.from_dict(data=userdoc)
        self._reset_databases()
        super().tearDown()


class AsyncMongoTestCase(unittest.IsolatedAsyncioTestCase):
    """TestCase with an embedded MongoDB temporary instance.

    Each test runs on a temporary instance of MongoDB. The instance will
    be listen in a random port between 40000 and 50000.

    A test can access the connection using the attribute `conn`.
    A test can access the port using the attribute `port`
    """

    def setUp(self, *args: list[Any], **kwargs: dict[str, Any]) -> None:
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

    def _init_logging(self) -> None:
        # Only initialize logging once to avoid creating multiple handlers
        # that reference pytest's captured streams which get closed during test execution
        if logging.getLogger().handlers:
            return
        local_context = LocalContext(
            app_debug=True,
            app_name="testing",
            format="{asctime} | {levelname:7} |             | {name:35} | {message}",
            level="DEBUG",
            relative_time=True,
        )
        logging_config = make_dictConfig(local_context)
        logging.config.dictConfig(logging_config)

    def _reset_databases(self) -> None:
        """
        Reset databases for the next test class.

        We do this both at shutdown (to clean up) and in setUp() to make sure that tests get a clean environment.
        Particularly vscode doesn't always run tearDown(), when tests fails or the debugger is stopped mid-test.
        """
        for db_name in self.tmp_db.conn.list_database_names():
            if db_name not in ["local", "admin", "config"]:  # Do not drop mongo internal dbs
                self.tmp_db.conn.drop_database(db_name)

    def tearDown(self) -> None:
        self._reset_databases()
        super().tearDown()
