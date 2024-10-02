"""Test worker that just logs received items"""

import asyncio
import logging
import os
from asyncio import Task
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from eduid.common.config.parsers import load_config
from eduid.queue.config import QueueWorkerConfig
from eduid.queue.db import QueueItem, SenderInfo
from eduid.queue.db.message.payload import EduidTestPayload, EduidTestResultPayload
from eduid.queue.workers.base import QueueWorker
from eduid.userdb.util import utc_now

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class SinkQueueWorker(QueueWorker):
    def __init__(self, config: QueueWorkerConfig):
        # Register which queue items this worker should try to grab
        payloads = [EduidTestPayload]
        super().__init__(config=config, handle_payloads=payloads)

        self._receiving = False
        self._counter = 0
        self._first_ts: datetime | None = None
        self._last_ts: datetime | None = None
        hostname = os.environ.get("HOSTNAME") or "localhost"
        self._sender_info = SenderInfo(hostname=hostname, node_id="sink_worker")

    async def handle_new_item(self, queue_item: QueueItem) -> None:
        if queue_item.payload_type == EduidTestPayload.get_type():
            self._receiving = True
            logger.debug(f"Received queue item: {queue_item.item_id}")
            logger.debug(queue_item)
            now = utc_now()
            if not self._first_ts:
                self._first_ts = now
            self._counter += 1
            self._last_ts = now

        await self.item_successfully_handled(queue_item)

    async def handle_expired_item(self, queue_item: QueueItem) -> None:
        logger.warning(f"Found expired item: {queue_item}")

    async def collect_periodic_tasks(self) -> set[Task]:
        tasks = await super().collect_periodic_tasks()
        self.add_task(tasks, asyncio.create_task(self.periodic_stats_publishing(), name="periodic_stats_publishing"))
        return tasks

    async def periodic_stats_publishing(self) -> None:
        if not self._receiving and (self._counter and self._first_ts and self._last_ts):
            # publish statistics when no longer receiving new items for a whole period

            delta = self._last_ts - self._first_ts
            per_second = self._counter / delta.total_seconds()
            payload = EduidTestResultPayload(
                counter=self._counter,
                first_ts=self._first_ts,
                last_ts=self._last_ts,
                delta=str(delta),
                per_second=int(per_second),
            )
            self._first_ts = None
            self._last_ts = None
            self._counter = 0

            now = utc_now()
            qitem = QueueItem(
                version=1,
                expires_at=now + timedelta(seconds=3),
                discard_at=now + timedelta(seconds=6),
                sender_info=self._sender_info,
                payload_type=payload.get_type(),
                payload=payload,
            )
            logger.info(f"Test results this period: {payload}")
            await self.db.save(qitem)

        self._receiving = False


def init_sink_worker(name: str = "sink_worker", test_config: Mapping[str, Any] | None = None) -> SinkQueueWorker:
    config = load_config(typ=QueueWorkerConfig, app_name=name, ns="queue", test_config=test_config)
    return SinkQueueWorker(config=config)


def start_worker() -> None:
    worker = init_sink_worker()
    exit(asyncio.run(worker.run()))


if __name__ == "__main__":
    logger = logging.getLogger("sink-queue-worker")
    start_worker()
