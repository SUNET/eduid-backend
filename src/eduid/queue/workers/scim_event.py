import asyncio
import json
import logging
from collections.abc import Mapping
from typing import Any, cast

import httpx

from eduid.common.config.parsers import load_config
from eduid.queue.config import QueueWorkerConfig
from eduid.queue.db import QueueItem
from eduid.queue.db.message.payload import EduidSCIMAPINotification
from eduid.queue.db.queue_item import Status
from eduid.queue.workers.base import QueueWorker

logger = logging.getLogger(__name__)

__author__ = "ft"


class ScimEventQueueWorker(QueueWorker):
    def __init__(self, config: QueueWorkerConfig):
        # Register which queue items this worker should try to grab
        payloads = [EduidSCIMAPINotification]
        super().__init__(config=config, handle_payloads=payloads)

    async def handle_new_item(self, queue_item: QueueItem) -> None:
        logger.debug(f"handle_new_item: {queue_item}")
        status = None
        if queue_item.payload_type == EduidSCIMAPINotification.get_type():
            status = await self.send_scim_notification(
                cast(
                    EduidSCIMAPINotification,
                    queue_item.payload,
                )
            )
            logger.debug(f"send_scim_notification returned status: {status}")

        if status and status.retry:
            logger.info(f"Retrying queue item: {queue_item.item_id}")
            logger.debug(queue_item)
            await self.retry_item(queue_item)
            return

        await self.item_successfully_handled(queue_item)

    async def handle_expired_item(self, queue_item: QueueItem) -> None:
        logger.warning(f"Found expired item: {queue_item}")

    async def send_scim_notification(self, data: EduidSCIMAPINotification) -> Status:
        logger.debug(f"send_scim_notification: {data}")
        async with httpx.AsyncClient() as client:
            r = client.post(data.post_url, json=json.loads(data.message))
            logger.debug(f"send_scim_notification: HTTPX result: {r}")
        return Status(success=True, message="OK")


def init_scim_event_worker(
    name: str = "scim_event_worker", test_config: Mapping[str, Any] | None = None
) -> ScimEventQueueWorker:
    config = load_config(typ=QueueWorkerConfig, app_name=name, ns="queue", test_config=test_config)
    return ScimEventQueueWorker(config=config)


def start_worker():
    worker = init_scim_event_worker()
    exit(asyncio.run(worker.run()))


if __name__ == "__main__":
    start_worker()
