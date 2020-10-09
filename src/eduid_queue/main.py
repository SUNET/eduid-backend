import asyncio
import functools
import logging
import signal
from asyncio import CancelledError
from datetime import datetime

from bson import ObjectId
from eduid_userdb.q import QueueItem, TestPayload
from motor.motor_asyncio import AsyncIOMotorClient

from eduid_queue.db import AsyncQueueDB, ChangeEvent, OperationType
from eduid_queue.log import init_logging
from eduid_queue.tasks import process_item

logger = logging.getLogger(__name__)


# TODO: Fix configuration
def get_worker_name():
    return 'eduid-queue-worker'


async def process_new_item(db: AsyncQueueDB, document_id: str, worker_name: str):
    """
    Sends queue item for processing and removes the item from the database on success
    """
    queue_item = await db.grab_item(document_id, worker_name=worker_name)
    if queue_item:
        try:
            queue_item: QueueItem = await process_item(queue_item)
        except Exception as e:
            logger.exception(f'QueueItem processing failed with: {repr(e)}')
            return
        # Processing successful, remove queue item
        timeit = datetime.utcnow() - queue_item.created_ts
        await db.remove_item(queue_item.item_id)
        logger.info(f'QueueItem with id: {queue_item.item_id} successfully processed after {timeit.seconds}s.')


async def handle_change(db: AsyncQueueDB, change: ChangeEvent):
    """
    Dispatch item for processing depending on change operation
    """
    document_id = change.document_key.id
    worker_name = get_worker_name()

    if change.operation_type == OperationType.INSERT:
        await process_new_item(db, document_id, worker_name)
    else:
        logger.debug(f'{change.operation_type.value}: {change}')


async def watch_collection(db):
    change_stream = None
    tasks = []
    try:
        async with db.collection.watch() as change_stream:
            async for change in change_stream:
                change_event = ChangeEvent.from_dict(change)
                tasks.append(asyncio.create_task(handle_change(db, change_event), name='handle_change'))
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


async def periodic_collection_check(db):
    # TODO: should be in config
    run_every_seconds = 10
    worker_name = get_worker_name()
    min_retry_wait_in_seconds = 10
    tasks = []
    try:
        while True:
            # Check for forgotten untouched queue items
            docs = await db.find_items(processed=False, min_age_in_seconds=min_retry_wait_in_seconds, expired=False)
            logger.debug(docs)
            for doc in docs:
                logger.info(f'{doc} was forgotten, processing it')
                document_id = doc['_id']
                tasks.append(
                    asyncio.create_task(
                        process_new_item(db=db, document_id=document_id, worker_name=worker_name),
                        name='periodic_process_new_item',
                    )
                )

            # TODO: Implement expired report or some kind of retry of failed events here

            tasks = [task for task in tasks if not task.done()]
            logger.debug(f'periodic_collection_check: {len(tasks)} running tasks')
            logger.debug(f'periodic_collection_check: sleeping for {run_every_seconds}s')
            await asyncio.sleep(run_every_seconds)
    except CancelledError:
        logger.info('periodic_collection_check task was cancelled')
    finally:
        # Wait for tasks to finish before exiting
        logger.info('Cleaning up periodic_collection_check task...')
        await asyncio.gather(*tasks)


async def run_tasks(db: AsyncQueueDB):
    logger.info(f'Initiating event stream for: {db}')
    watch_collection_task = asyncio.create_task(watch_collection(db), name=f'Watch collection {db._coll_name}')
    logger.info(f'Initiating periodic tasks: {db}')
    periodic_task = asyncio.create_task(periodic_collection_check(db), name=f'Periodic check for {db._coll_name}')
    try:
        await asyncio.gather(watch_collection_task, periodic_task)
    except CancelledError:
        logger.info('run_tasks task was cancelled')


def cancel_task(signame, task):
    logger.info("got signal %s: exit" % signame)
    task.cancel()


async def main():
    mongo_uri = 'mongodb://localhost:43444'
    collection = 'test'
    db = AsyncQueueDB(db_uri=mongo_uri, collection=collection, connection_factory=AsyncIOMotorClient)
    db.register_handler(payload=TestPayload)

    main_task = asyncio.create_task(run_tasks(db), name=f'run all tasks')
    # set up signal handling to be a well behaved service
    loop = asyncio.get_running_loop()
    for signame in {'SIGINT', 'SIGTERM'}:
        loop.add_signal_handler(getattr(signal, signame), functools.partial(cancel_task, signame, main_task))

    logger.info(f'Running: {main_task.get_name()}')
    await main_task


if __name__ == '__main__':
    init_logging(app_name=get_worker_name())
    exit(asyncio.run(main()))
