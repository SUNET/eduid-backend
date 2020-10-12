# -*- coding: utf-8 -*-

import asyncio
import functools
import logging
import signal
from abc import ABC
from asyncio import CancelledError
from datetime import datetime
from typing import List, Type, Optional

from eduid_common.config.workers import QueueWorkerConfig
from eduid_userdb.q import Payload, QueueItem
from motor.motor_asyncio import AsyncIOMotorClient

from eduid_queue.db import AsyncQueueDB, ChangeEvent, OperationType
from eduid_queue.log import init_logging

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


def cancel_task(signame, task):
    logger.info("got signal %s: exit" % signame)
    task.cancel()


class QueueWorker(ABC):
    def __init__(self, config: QueueWorkerConfig, handle_payloads: List[Type[Payload]]):
        self.config = config
        self.payloads = handle_payloads
        self.db: Optional[AsyncQueueDB] = None

        init_logging(app_name=config.app_name, config=self.config.logging_config)
        logger.info(f'Starting {self.config.app_name}: {self.config.worker_name}...')

    async def run(self):
        # Init db in the correct loop
        self.db = AsyncQueueDB(
            db_uri=self.config.mongo_uri, collection=self.config.mongo_collection, connection_factory=AsyncIOMotorClient
        )
        # Register payloads to handle
        for payload in self.payloads:
            self.db.register_handler(payload)

        # Create a main task for easy cleanup when exiting
        main_task = asyncio.create_task(self.run_subtasks(), name=f'run subtasks')
        # set up signal handling to be a well behaved service
        loop = asyncio.get_running_loop()
        for signame in {'SIGINT', 'SIGTERM'}:
            loop.add_signal_handler(getattr(signal, signame), functools.partial(cancel_task, signame, main_task))

        logger.info(f'Running: {main_task.get_name()}')
        await main_task

    async def run_subtasks(self):
        logger.info(f'Initiating event stream for: {self.db}')
        watch_collection_task = asyncio.create_task(
            self.watch_collection(), name=f'Watch collection {self.config.mongo_collection}'
        )
        logger.info(f'Initiating periodic tasks for: {self.db}')
        periodic_task = asyncio.create_task(
            self.periodic_collection_check(), name=f'Periodic check for {self.config.mongo_collection}'
        )
        try:
            await asyncio.gather(watch_collection_task, periodic_task)
        except CancelledError:
            logger.info('run_tasks task was cancelled')

    async def process_new_item(self, document_id: str):
        """
        Sends queue item for processing and removes the item from the database on success
        """
        assert self.db  # Please mypy
        queue_item = await self.db.grab_item(document_id, worker_name=self.config.worker_name)
        if queue_item:
            try:
                queue_item = await self.handle_new_item(queue_item)
            except Exception as e:
                logger.exception(f'QueueItem processing failed with: {repr(e)}')
                return
            # Processing successful, remove queue item
            timeit = datetime.utcnow() - queue_item.created_ts
            await self.db.remove_item(queue_item.item_id)
            logger.info(f'QueueItem with id: {queue_item.item_id} successfully processed after {timeit.seconds}s.')

    async def handle_change(self, change: ChangeEvent):
        """
        Dispatch item for processing depending on change operation
        """
        if change.operation_type == OperationType.INSERT:
            await self.process_new_item(change.document_key.id)
        else:
            logger.debug(f'{change.operation_type.value}: {change}')

    async def watch_collection(self):
        change_stream = None
        tasks = []
        try:
            async with self.db.collection.watch() as change_stream:
                async for change in change_stream:
                    change_event = ChangeEvent.from_dict(change)
                    tasks.append(asyncio.create_task(self.handle_change(change_event), name='handle_change'))
                    tasks = [task for task in tasks if not task.done()]
                    logger.debug(f'watch_collection: {len(tasks)} running tasks')
        except CancelledError:
            logger.info('watch_collection task was cancelled')
        finally:
            if change_stream is not None:
                logger.info('Closing watch stream...')
                await change_stream.close()
                # Wait for tasks to finish before exiting
                logger.info('Cleaning up watch_collection task...')
                await asyncio.gather(*tasks)

    async def periodic_collection_check(self):
        tasks = []
        try:
            while True:
                logger.debug(f'Running periodic collection check')
                # Check for forgotten untouched queue items
                items = await self.db.find_items(
                    processed=False, min_age_in_seconds=self.config.periodic_min_retry_wait_in_seconds, expired=False
                )
                logger.debug(f'found items: {items}')
                for item in items:
                    logger.info(f'{item} was forgotten, processing it')
                    tasks.append(
                        asyncio.create_task(
                            self.process_new_item(document_id=item['_id']),
                            name='periodic_process_new_item',
                        )
                    )

                # TODO: Implement expired report or some kind of retry of failed events here

                tasks = [task for task in tasks if not task.done()]
                logger.debug(f'periodic_collection_check: {len(tasks)} running tasks')
                logger.debug(f'periodic_collection_check: sleeping for {self.config.periodic_interval}s')
                await asyncio.sleep(self.config.periodic_interval)
        except CancelledError:
            logger.info('periodic_collection_check task was cancelled')
        finally:
            # Wait for tasks to finish before exiting
            logger.info('Cleaning up periodic_collection_check task...')
            await asyncio.gather(*tasks)

    async def handle_new_item(self, queue_item: QueueItem) -> QueueItem:
        raise NotImplementedError()

    async def handle_expired_item(self, queue_item: QueueItem) -> QueueItem:
        raise NotImplementedError()
