# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import logging
import time
from asyncio import Task
from datetime import datetime, timedelta
from typing import List, Optional, Sequence, Type, cast
from unittest import IsolatedAsyncioTestCase, TestCase

import pymongo
from pymongo.errors import NotPrimaryError

from eduid.common.misc.timeutil import utc_now
from eduid.queue.db import Payload, QueueDB, QueueItem, SenderInfo
from eduid.userdb.testing import MongoTemporaryInstance

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class MongoTemporaryInstanceReplicaSet(MongoTemporaryInstance):
    rs_initialized = False

    def __init__(self, max_retry_seconds: int):
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
            "docker.sunet.se/eduid/mongodb:latest",
        ]

    def setup_conn(self) -> bool:
        try:
            if not self.rs_initialized:
                # Just try to initialize replica set once
                tmp_conn: pymongo.MongoClient = pymongo.MongoClient(
                    host="localhost", port=self.port, directConnection=True
                )
                # Start replica set and set hostname to localhost
                config = {
                    "_id": "rs0",
                    "members": [{"_id": 0, "host": f"localhost:{self.port}"}],
                }
                tmp_conn.admin.command("replSetInitiate", config)
                tmp_conn.close()
                self.rs_initialized = True
            self._conn = pymongo.MongoClient(host="localhost", port=self.port, replicaSet="rs0")
        except pymongo.errors.ConnectionFailure as e:
            with self._logfile as f:
                try:
                    f.writelines([str(e)])
                except ValueError:
                    logger.exception(f"Failed to write to logfile {self._logfile}")
                    logger.error(f"message was: {e}")
            return False
        return True

    @classmethod
    def get_instance(
        cls: Type[MongoTemporaryInstanceReplicaSet], max_retry_seconds: int = 60
    ) -> MongoTemporaryInstanceReplicaSet:
        return cast(MongoTemporaryInstanceReplicaSet, super().get_instance(max_retry_seconds=max_retry_seconds))

    @property
    def uri(self):
        return f"mongodb://localhost:{self.port}"


class EduidQueueTestCase(TestCase):
    mongo_instance: MongoTemporaryInstanceReplicaSet
    mongo_uri: str
    mongo_collection: str
    db: QueueDB

    @classmethod
    def setUpClass(cls) -> None:
        cls.mongo_instance = MongoTemporaryInstanceReplicaSet.get_instance()

    def setUp(self) -> None:
        self.mongo_uri = self.mongo_instance.uri
        self.mongo_collection = "test"
        self._init_db()

    def tearDown(self) -> None:
        self.db._drop_whole_collection()

    def _init_db(self):
        db_init_try = 0
        while True:
            try:
                self.db = QueueDB(db_uri=self.mongo_uri, collection=self.mongo_collection)
                break
            except NotPrimaryError as e:
                db_init_try += 1
                time.sleep(db_init_try)
                if db_init_try >= 10:
                    raise e
                continue


class QueueAsyncioTest(EduidQueueTestCase, IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tasks: List[Task] = []

    async def asyncTearDown(self) -> None:
        for task in self.tasks:
            if not task.done():
                task.cancel()

    @staticmethod
    def create_queue_item(expires_at: datetime, discard_at: datetime, payload: Payload):
        sender_info = SenderInfo(hostname="localhost", node_id="test")
        return QueueItem(
            version=1,
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload_type=payload.get_type(),
            payload=payload,
        )

    async def _assert_item_gets_processed(self, queue_item: QueueItem, retry: bool = False):
        end_time = utc_now() + timedelta(seconds=10)
        fetched: Optional[QueueItem] = None
        while utc_now() < end_time:
            await asyncio.sleep(0.5)  # Allow worker to run
            fetched = self.db.get_item_by_id(queue_item.item_id)
            if not fetched:
                logger.info(f"Queue item {queue_item.item_id} was processed")
                break
            if retry:
                assert fetched is not None
                return None
            logger.info(f"Queue item {queue_item.item_id} not processed yet")
        assert fetched is None
