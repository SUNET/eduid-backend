from __future__ import annotations

import asyncio
import logging
import time
from asyncio import Task
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch

import pymongo
import pymongo.errors

from eduid.common.misc.timeutil import utc_now
from eduid.queue.db import Payload, QueueDB, QueueItem, SenderInfo
from eduid.queue.db.worker import AsyncQueueDB
from eduid.queue.workers.base import QueueWorker
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.testing import EduidTemporaryInstance, MongoTemporaryInstance

__author__ = "lundberg"

logger = logging.getLogger(__name__)

MAX_INIT_TRIES = 10


class MongoTemporaryInstanceReplicaSet(MongoTemporaryInstance):
    rs_initialized = False

    def __init__(self, max_retry_seconds: int) -> None:
        super().__init__(max_retry_seconds=max_retry_seconds)

    @property
    def command(self) -> Sequence[str]:
        return [
            "docker",
            "run",
            "--rm",
            "-p",
            f"{self.port}:{self.port}",
            "-e",
            "REPLSET=yes",
            "-e",
            f"PORT={self.port}",
            "--name",
            f"test_mongodb_rs_{self.port}",
            "docker.sunet.se/eduid/mongodb:latest",
        ]

    def setup_conn(self) -> bool:
        try:
            if not self.rs_initialized:
                # Just try to initialize replica set once
                tmp_conn = pymongo.MongoClient[TUserDbDocument](host="localhost", port=self.port, directConnection=True)
                # Start replica set and set hostname to localhost
                config = {
                    "_id": "rs0",
                    "members": [{"_id": 0, "host": f"localhost:{self.port}"}],
                }
                res: Any = tmp_conn.admin.command("replSetInitiate", config)
                logger.debug(f"replSetInitiate result: {res}")
                tmp_conn.close()
                self.rs_initialized = True
            self._conn = pymongo.MongoClient[TUserDbDocument](host="localhost", port=self.port, replicaSet="rs0")
        except Exception as e:
            logger.exception("Failed to initiate replica set, or connect to it")
            with self._logfile as f:
                try:
                    f.writelines([str(e)])
                except ValueError:
                    logger.exception(f"Failed to write to logfile {self._logfile}")
                    logger.error(f"message was: {e}")
            return False
        return True

    @property
    def uri(self) -> str:
        return f"mongodb://localhost:{self.port}"


class SMPTDFixTemporaryInstance(EduidTemporaryInstance):
    def __init__(self, max_retry_seconds: int) -> None:
        super().__init__(max_retry_seconds=max_retry_seconds)

    @property
    def command(self) -> Sequence[str]:
        return [
            "docker",
            "run",
            "--rm",
            "-p",
            f"{self.port}:8025",
            "--name",
            f"test_smtpdfix_{self.port}",
            "docker.sunet.se/eduid/smtpdfix:latest",
        ]

    def setup_conn(self) -> bool:
        return True

    @property
    def conn(self) -> None:
        return None


class EduidQueueTestCase(TestCase):
    mongo_instance: MongoTemporaryInstanceReplicaSet
    mongo_uri: str
    mongo_collection: str
    client_db: QueueDB

    @classmethod
    def setUpClass(cls) -> None:
        cls.mongo_instance = MongoTemporaryInstanceReplicaSet.get_instance()

    def setUp(self) -> None:
        self.mongo_uri = self.mongo_instance.uri
        self.mongo_collection = "test"
        self._init_db()

    def tearDown(self) -> None:
        self.client_db._drop_whole_collection()

    def _init_db(self) -> None:
        db_init_try = 0
        while True:
            try:
                self.client_db = QueueDB(db_uri=self.mongo_uri, collection=self.mongo_collection)
                break
            except pymongo.errors.NotPrimaryError as e:
                db_init_try += 1
                time.sleep(db_init_try)
                if db_init_try >= MAX_INIT_TRIES:
                    raise e
                continue


class QueueAsyncioTest(EduidQueueTestCase, IsolatedAsyncioTestCase):
    worker_db: AsyncQueueDB

    async def asyncSetUp(self) -> None:
        self.tasks: list[Task] = []
        await self._init_async_db()

    async def asyncTearDown(self) -> None:
        for task in self.tasks:
            if not task.done():
                task.cancel()

    async def _init_async_db(self) -> None:
        db_init_try = 0
        while True:
            try:
                # Make sure the isolated test cases get to create their own mongodb clients
                with patch("eduid.userdb.db.async_db.AsyncClientCache._clients", {}):
                    self.worker_db = await AsyncQueueDB.create(db_uri=self.mongo_uri, collection=self.mongo_collection)
                break
            except pymongo.errors.NotPrimaryError as e:
                db_init_try += 1
                await asyncio.sleep(db_init_try)
                if db_init_try >= MAX_INIT_TRIES:
                    raise e
                continue

    @staticmethod
    def create_queue_item(expires_at: datetime, discard_at: datetime, payload: Payload) -> QueueItem:
        sender_info = SenderInfo(hostname="localhost", node_id="test")
        return QueueItem(
            version=1,
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload_type=payload.get_type(),
            payload=payload,
        )

    async def _assert_item_gets_processed(self, queue_item: QueueItem, retry: bool = False) -> None:
        end_time = utc_now() + timedelta(seconds=10)
        fetched: QueueItem | None = None
        while utc_now() < end_time:
            await asyncio.sleep(0.5)  # Allow worker to run
            fetched = self.client_db.get_item_by_id(queue_item.item_id)
            if not fetched:
                logger.info(f"Queue item {queue_item.item_id} was processed")
                break
            if retry:
                assert fetched is not None
                return None
            logger.info(f"Queue item {queue_item.item_id} not processed yet")
        assert fetched is None


class IsolatedWorkerDBMixin(QueueWorker):
    # override run so we can mock cache of database clients
    async def run(self) -> None:
        # Init db in the correct loop
        # Make sure the isolated test cases get to create their own mongodb clients
        with patch("eduid.userdb.db.async_db.AsyncClientCache._clients", {}):
            await super().run()
