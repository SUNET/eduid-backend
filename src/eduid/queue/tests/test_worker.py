import asyncio
import logging
import os
from datetime import timedelta
from os import environ

from eduid.common.config.parsers import load_config
from eduid.common.misc.timeutil import utc_now
from eduid.queue.config import QueueWorkerConfig
from eduid.queue.db import QueueItem, TestPayload
from eduid.queue.testing import IsolatedWorkerDBMixin, QueueAsyncioTest
from eduid.queue.workers.base import QueueWorker

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class QueueTestWorker(IsolatedWorkerDBMixin, QueueWorker):
    async def handle_expired_item(self, queue_item: QueueItem) -> None:
        if not isinstance(queue_item.payload, TestPayload):
            raise Exception(f"queue_item.payload type {type(queue_item.payload)} not TestPayload")
        assert queue_item.payload.message == "Expired item"
        await self.item_successfully_handled(queue_item)

    async def handle_new_item(self, queue_item: QueueItem) -> None:
        if not isinstance(queue_item.payload, TestPayload):
            raise Exception(f"queue_item.payload type {type(queue_item.payload)} not TestPayload")
        assert queue_item.payload.message == "New item"
        await self.item_successfully_handled(queue_item)


class TestBaseWorker(QueueAsyncioTest):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        environ["WORKER_NAME"] = "Test Worker 1"

    def setUp(self) -> None:
        super().setUp()
        self.test_config = {
            "testing": True,
            "mongo_uri": self.mongo_uri,
            "mongo_collection": self.mongo_collection,
            "periodic_min_retry_wait_in_seconds": 1,
        }

        if "EDUID_CONFIG_YAML" not in os.environ:
            os.environ["EDUID_CONFIG_YAML"] = "YAML_CONFIG_NOT_USED"

        self.config = load_config(typ=QueueWorkerConfig, app_name="test", ns="queue", test_config=self.test_config)
        self.client_db.register_handler(TestPayload)

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.worker_db.register_handler(TestPayload)
        await asyncio.sleep(0.5)  # wait for db
        self.worker = QueueTestWorker(config=self.config, handle_payloads=[TestPayload])
        self.tasks = [asyncio.create_task(self.worker.run())]
        await asyncio.sleep(0.5)  # wait for worker to initialize

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()

    async def test_worker_item_from_stream(self) -> None:
        """
        Test that saved queue items are handled by the handle_new_item method
        """
        expires_at = utc_now() + timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=5)
        payload = TestPayload(message="New item")
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        # Client saves new queue item
        self.client_db.save(queue_item)
        await self._assert_item_gets_processed(queue_item)

    async def test_worker_expired_item(self) -> None:
        """
        Test that expired queue items are handled by the handle_expired_item method
        """
        # Stop running worker
        for task in self.tasks:
            task.cancel()
        expires_at = utc_now() - timedelta(minutes=5)
        discard_at = expires_at + timedelta(minutes=10)
        payload = TestPayload(message="Expired item")
        queue_item = self.create_queue_item(expires_at, discard_at, payload)
        # Fake that a client have saved queue item in the past
        self.client_db.save(queue_item)
        # Start worker after save to fake that the item has expired unhandled in the queue
        self.tasks = [asyncio.create_task(self.worker.run())]
        await self._assert_item_gets_processed(queue_item)
