# -*- coding: utf-8 -*-
from __future__ import annotations

import time
from asyncio import Task
from datetime import datetime
from typing import List, Sequence, Type, cast
from unittest import IsolatedAsyncioTestCase, TestCase

import pymongo
from pymongo.errors import NotMasterError

from eduid.queue.db import Payload, QueueDB, QueueItem, SenderInfo
from eduid.userdb.testing import MongoTemporaryInstance

__author__ = 'lundberg'


class MongoTemporaryInstanceReplicaSet(MongoTemporaryInstance):
    rs_initialized = False

    def __init__(self, max_retry_seconds: int):
        super().__init__(max_retry_seconds=max_retry_seconds)

    @property
    def command(self) -> Sequence[str]:
        return [
            'docker',
            'run',
            '--rm',
            '-p',
            f'{self.port}:27017',
            '-e',
            'REPLSET=yes',
            'docker.sunet.se/eduid/mongodb:latest',
        ]

    def setup_conn(self) -> bool:
        try:
            if not self.rs_initialized:
                # Just try to initialize replica set once
                tmp_conn = pymongo.MongoClient('localhost', self.port)
                # Start replica set
                tmp_conn.admin.command("replSetInitiate")
                tmp_conn.close()
                self.rs_initialized = True
            self._conn = pymongo.MongoClient(host='localhost', port=self.port, replicaSet='rs0')
        except pymongo.errors.ConnectionFailure as e:
            with self._logfile as f:
                f.writelines([str(e)])
            return False
        return True

    @classmethod
    def get_instance(
        cls: Type[MongoTemporaryInstanceReplicaSet], max_retry_seconds: int = 60
    ) -> MongoTemporaryInstanceReplicaSet:
        return cast(MongoTemporaryInstanceReplicaSet, super().get_instance(max_retry_seconds=max_retry_seconds))

    @property
    def uri(self):
        return f'mongodb://localhost:{self.port}'


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
        self.mongo_collection = 'test'
        self._init_db()

    def tearDown(self) -> None:
        self.db._drop_whole_collection()

    def _init_db(self):
        db_init_try = 0
        while True:
            try:
                self.db = QueueDB(db_uri=self.mongo_uri, collection=self.mongo_collection)
                break
            except NotMasterError as e:
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
        sender_info = SenderInfo(hostname='localhost', node_id='test')
        return QueueItem(
            version=1,
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload_type=payload.get_type(),
            payload=payload,
        )
