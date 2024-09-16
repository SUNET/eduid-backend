import asyncio
import functools
import logging
import signal
from abc import ABC
from asyncio import CancelledError, Task
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from os import environ

from eduid.common.logging import init_logging
from eduid.queue.config import QueueWorkerConfig
from eduid.queue.db import QueueItem
from eduid.queue.db.change_event import ChangeEvent, OperationType
from eduid.queue.db.payload import Payload
from eduid.queue.db.worker import AsyncQueueDB

__author__ = "lundberg"

logger = logging.getLogger(__name__)


def cancel_task(signame, task):
    logger.info(f"got signal {signame}: exit")
    task.cancel()


class QueueWorker(ABC):
    def __init__(self, config: QueueWorkerConfig, handle_payloads: Sequence[type[Payload]]):
        worker_name = environ.get("WORKER_NAME", None)
        if worker_name is None:
            raise RuntimeError("Environment variable WORKER_NAME needs to be set")
        self.worker_name = worker_name
        self.config = config
        self.payloads = handle_payloads
        self.db: AsyncQueueDB

        init_logging(config=config)
        logger.info(f"Starting {self.config.app_name}: {self.worker_name}...")

    @staticmethod
    def add_task(tasks: set[Task], task: Task) -> set[Task]:
        # To prevent keeping references to finished tasks forever, make each task remove its own reference
        # from the set after completion.
        task.add_done_callback(tasks.discard)
        tasks.add(task)
        return tasks

    async def run(self):
        # Init db in the correct loop
        self.db = await AsyncQueueDB.create(db_uri=self.config.mongo_uri, collection=self.config.mongo_collection)
        # Register payloads to handle
        for payload in self.payloads:
            self.db.register_handler(payload)

        # Create a main task for easy cleanup when exiting
        main_task = asyncio.create_task(self.run_subtasks(), name="run subtasks")
        # set up signal handling to be a well behaved service
        loop = asyncio.get_running_loop()
        for signame in {"SIGINT", "SIGTERM"}:
            loop.add_signal_handler(getattr(signal, signame), functools.partial(cancel_task, signame, main_task))

        logger.info(f"Running: {main_task.get_name()}")
        await main_task

    async def run_subtasks(self):
        logger.info(f"Initiating event stream for: {self.db}")
        watch_collection_task = asyncio.create_task(
            self.watch_collection(), name=f"Watch collection {self.config.mongo_collection}"
        )
        logger.info(f"Initiating periodic tasks for: {self.db}")
        periodic_task = asyncio.create_task(
            self.periodic_collection_check(), name=f"Periodic check for {self.config.mongo_collection}"
        )
        try:
            await asyncio.gather(watch_collection_task, periodic_task)
        except CancelledError:
            logger.info("run_tasks task was cancelled")

    async def item_successfully_handled(self, queue_item: QueueItem) -> None:
        """
        Removes the queue item from the database
        """
        timeit = datetime.utcnow() - queue_item.created_ts
        await self.db.remove_item(queue_item.item_id)
        logger.info(f"QueueItem with id: {queue_item.item_id} successfully processed after {timeit.seconds}s.")

    async def retry_item(self, queue_item: QueueItem) -> None:
        """
        Increases the queue item retry counter and puts it back in the queue
        """
        # TODO: Should we add a state (retry) to the queue item in the database?
        retries = queue_item.retries + 1
        if retries <= self.config.max_retries:
            # Replace the queue item with a new one that can be grabbed by another worker
            new_queue_item = replace(queue_item, retries=retries, processed_by=None, processed_ts=None)
            success = await self.db.replace_item(queue_item, new_queue_item)
            if not success:
                logger.warning("Replacing QueueItem failed.")
                logger.warning(f"QueueItem with id: {queue_item.item_id} will NOT be retried.")
            logger.info(f"QueueItem with id: {queue_item.item_id} will be retried")

    async def process_new_item(self, document_id: str) -> None:
        """
        Sends queue item for processing and removes the item from the database on success
        """
        queue_item = await self.db.grab_item(document_id, worker_name=self.worker_name)
        if queue_item:
            try:
                await self.handle_new_item(queue_item)
            except Exception as e:
                logger.exception(f"QueueItem processing failed with: {repr(e)}")

    async def handle_change(self, change: ChangeEvent) -> None:
        """
        Dispatch item for processing depending on change operation
        """
        if change.operation_type == OperationType.INSERT:
            await self.process_new_item(change.document_key.id)
        else:
            logger.debug(f"{change.operation_type.value}: {change}")

    async def watch_collection(self) -> None:
        change_stream = None
        tasks: set[Task] = set()
        try:
            async with self.db.collection.watch() as change_stream:
                async for change in change_stream:
                    change_event = ChangeEvent.from_dict(change)
                    tasks = self.add_task(
                        tasks,
                        asyncio.create_task(self.handle_change(change_event), name="handle_change"),
                    )
                    # Setting the delay to 0 provides an optimized path to allow other tasks to run.
                    await asyncio.sleep(0)
                    logger.info(f"watch_collection: {len(tasks)} running tasks")
        except CancelledError:
            logger.info("watch_collection task was cancelled")
        finally:
            if change_stream is not None:
                logger.info("Closing watch stream...")
                await change_stream.close()
                # Wait for tasks to finish before exiting
                logger.info("Cleaning up watch_collection task...")
                await asyncio.gather(*tasks)

    async def periodic_collection_check(self) -> None:
        tasks: set[Task] = set()
        try:
            while True:
                logger.debug("Running periodic collection check")
                tasks = await self.collect_periodic_tasks()

                # TODO: Implement some kind of retry of failed events here

                logger.debug(f"periodic_collection_check: {len(tasks)} running tasks")
                logger.debug(f"periodic_collection_check: sleeping for {self.config.periodic_interval}s")
                await asyncio.sleep(self.config.periodic_interval)
        except CancelledError:
            logger.info("periodic_collection_check task was cancelled")
        finally:
            # Wait for tasks to finish before exiting
            logger.info("Cleaning up periodic_collection_check task...")
            await asyncio.gather(*tasks)

    async def collect_periodic_tasks(self) -> set[Task]:
        tasks = await self.collect_forgotten_items()
        tasks.update(await self.collect_expired_items())
        return tasks

    async def collect_forgotten_items(self) -> set[Task]:
        tasks: set[Task] = set()
        # Check for forgotten untouched queue items
        items = await self.db.find_items(
            processed=False, min_age_in_seconds=self.config.periodic_min_retry_wait_in_seconds, expired=False
        )
        if len(items) > 0:
            logger.info(f"{len(items)} item(s) was forgotten or should be retried, processing...")
        for item in items:
            logger.debug(f"item: {item}")
            tasks = self.add_task(
                tasks,
                asyncio.create_task(self.process_new_item(document_id=item["_id"]), name="periodic_process_new_item"),
            )
        return tasks

    async def collect_expired_items(self) -> set[Task]:
        tasks: set[Task] = set()
        # Check for expired untouched queue items
        items = await self.db.find_items(
            processed=False, min_age_in_seconds=self.config.periodic_min_retry_wait_in_seconds, expired=True
        )
        if len(items) > 0:
            logger.info(f"{len(items)} item(s) was not processed and has expired")
        for item in items:
            queue_item = await self.db.grab_item(item_id=item["_id"], worker_name=self.worker_name)
            if queue_item:
                tasks = self.add_task(
                    tasks,
                    asyncio.create_task(self.handle_expired_item(queue_item), name="periodic_process_expired_item"),
                )
        return tasks

    async def handle_new_item(self, queue_item: QueueItem) -> None:
        raise NotImplementedError()

    async def handle_expired_item(self, queue_item: QueueItem) -> None:
        raise NotImplementedError()
