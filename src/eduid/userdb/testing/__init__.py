"""
Code used in unit tests of various eduID applications.
"""

from __future__ import annotations

import logging
import logging.config
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

import pymongo
import pymongo.errors
import pytest

from eduid.common.logging import LocalContext, make_dict_config
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


class MongoTestCase:
    """TestCase with an embedded MongoDB temporary instance.

    Each test runs on a temporary instance of MongoDB. The instance will
    be listen in a random port between 40000 and 50000.

    A test can access the connection using the attribute `conn`.
    A test can access the port using the attribute `port`
    """

    @pytest.fixture(autouse=True)
    def setup_mongo(self, mongo_instance: MongoTemporaryInstance) -> Iterator[None]:
        self._init_logging()

        self.tmp_db = mongo_instance
        assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy
        self.amdb = AmDB(self.tmp_db.uri)

        logger.info("Resetting all databases for new tests")
        self._reset_databases()

        self.settings: dict[str, Any] = {
            "mongo_replicaset": None,
            "mongo_uri": self.tmp_db.uri,
        }

        yield

        for userdoc in self.amdb._get_all_docs():
            assert User.from_dict(data=userdoc)

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
        logging_config = make_dict_config(local_context)
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


class AsyncMongoTestCase:
    """TestCase with an embedded MongoDB temporary instance for async tests.

    Each test runs on a temporary instance of MongoDB. The instance will
    be listen in a random port between 40000 and 50000.

    A test can access the connection using the attribute `conn`.
    A test can access the port using the attribute `port`
    """

    @pytest.fixture(autouse=True)
    def setup_async_mongo(
        self, mongo_instance: MongoTemporaryInstance, isolated_async_client_cache: None
    ) -> Iterator[None]:
        self._init_logging()

        self.tmp_db = mongo_instance
        assert isinstance(self.tmp_db, MongoTemporaryInstance)  # please mypy

        logger.info("Resetting all databases for new tests")
        self._reset_databases()

        self.settings: dict[str, Any] = {
            "mongo_replicaset": None,
            "mongo_uri": self.tmp_db.uri,
        }

        yield

        self._reset_databases()

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
        logging_config = make_dict_config(local_context)
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
