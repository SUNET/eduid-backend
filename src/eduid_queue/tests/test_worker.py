# -*- coding: utf-8 -*-
import asyncio
from datetime import timedelta
from os import environ

from eduid_queue.config import QueueWorkerConfig
from eduid_queue.db import QueueItem, TestPayload
from eduid_queue.testing import QueueAsyncioTest
from eduid_queue.workers.base import QueueWorker
from eduid_userdb.util import utc_now

__author__ = 'lundberg'


class QueueTestWorker(QueueWorker):
    async def handle_expired_item(self, queue_item: QueueItem) -> None:
        if not isinstance(queue_item.payload, TestPayload):
            raise Exception(f'queue_item.payload type {type(queue_item.payload)} not TestPayload')
        assert queue_item.payload.message == 'Expired item'
        await self.item_successfully_handled(queue_item)

    async def handle_new_item(self, queue_item: QueueItem) -> None:
        if not isinstance(queue_item.payload, TestPayload):
            raise Exception(f'queue_item.payload type {type(queue_item.payload)} not TestPayload')
        assert queue_item.payload.message == 'New item'
        await self.item_successfully_handled(queue_item)


class TestBaseWorker(QueueAsyncioTest):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        environ['WORKER_NAME'] = 'Test Worker 1'

    def setUp(self) -> None:
        super().setUp()
        self.config = QueueWorkerConfig(
            testing=True,
            mongo_uri=self.mongo_uri,
            mongo_collection=self.mongo_collection,
            periodic_min_retry_wait_in_seconds=1,
        )
        self.db.register_handler(TestPayload)

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        await asyncio.sleep(2)  # wait for db
        self.worker = QueueTestWorker(config=self.config, handle_payloads=[TestPayload])
        self.tasks = [asyncio.create_task(self.worker.run())]
        await asyncio.sleep(1)  # wait for worker to initialize

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()

    async def test_worker_item_from_stream(self):
        expires_at = utc_now() + timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=5)
        payload = TestPayload(message='New item')
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        self.db.save(queue_item)
        await asyncio.sleep(1)  # Allow worker to run
        assert self.db.get_item_by_id(queue_item.item_id, raise_on_missing=False) is None

    async def test_worker_expired_item(self):
        # Stop running worker
        for task in self.tasks:
            task.cancel()
        expires_at = utc_now() - timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=10)
        payload = TestPayload(message='Expired item')
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        self.db.save(queue_item)
        # Start worker
        self.tasks = [asyncio.create_task(self.worker.run())]
        await asyncio.sleep(1)  # Allow worker to run
        assert self.db.get_item_by_id(queue_item.item_id, raise_on_missing=False) is None
