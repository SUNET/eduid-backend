# -*- coding: utf-8 -*-

import logging
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Union

from bson import ObjectId
from motor import motor_asyncio
from pymongo.results import UpdateResult

from eduid.queue.db import QueueDB, QueueItem
from eduid.queue.exceptions import PayloadNotRegistered
from eduid.userdb import MongoDB

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class MotorMongoDB(MongoDB):
    def get_database(self, database_name=None, username=None, password=None):
        """
        Can't call authenticate on a AsyncIOMotorDatabase
        """
        if database_name is None:
            database_name = self._database_name
        if database_name is None:
            raise ValueError('No database_name supplied, and no default provided to __init__')
        db = self._connection[database_name]
        return db


class AsyncQueueDB(QueueDB):
    def __init__(self, db_uri: str, collection: str, db_name: str = 'eduid_queue', connection_factory=None):
        super().__init__(db_uri, collection=collection, db_name=db_name)

        # Re-initialize database and collection with connection_factory
        self._db = MotorMongoDB(db_uri, db_name=db_name, connection_factory=connection_factory)
        self._coll = self._db.get_collection(collection=collection)

    @property
    def database(self) -> motor_asyncio.AsyncIOMotorDatabase:
        return self._db.get_database()

    @property
    def collection(self) -> motor_asyncio.AsyncIOMotorCollection:
        return self._coll

    @property
    def connection(self) -> motor_asyncio.AsyncIOMotorClient:
        return self._db.get_connection()

    def parse_queue_item(self, doc: Mapping, parse_payload: bool = True):
        item = QueueItem.from_dict(doc)
        if parse_payload is False:
            # Return the item with the generic RawPayload
            return item
        return replace(item, payload=self._load_payload(item))

    async def grab_item(self, item_id: Union[str, ObjectId], worker_name: str, regrab=False) -> Optional[QueueItem]:
        """
        :param item_id: document id
        :param worker_name: current workers name
        :param regrab: If True, try to grab an already processed item for reprocessing
        :return: queue item
        """
        logger.debug(f'Grabbing item for {worker_name}')

        if isinstance(item_id, str):
            item_id = ObjectId(item_id)

        spec = {
            '_id': item_id,
        }

        if not regrab:
            # Only try to grab previously untouched items
            spec['processed_by'] = None
            spec['processed_ts'] = None

        # Get item
        doc = await self.collection.find_one(spec)
        if not doc:
            return None

        if regrab:
            # Only replace items that still has the previous worker name and ts
            spec['processed_by'] = doc['processed_by']
            spec['processed_ts'] = doc['processed_ts']

        # Update item with current worker name and ts
        doc['processed_by'] = worker_name
        doc['processed_ts'] = datetime.now(tz=timezone.utc)

        try:
            # Try to parse the queue item to only grab items that are registered with the current db
            item = self.parse_queue_item(doc, parse_payload=True)
        except PayloadNotRegistered as e:
            logger.debug(e)
            return None

        update_result: UpdateResult = await self.collection.replace_one(spec, doc)
        logger.debug(f'result: {update_result.raw_result}')
        if not update_result.acknowledged or update_result.modified_count != 1:
            logger.debug(f'Grabbing of item failed: {update_result.raw_result}')
            return None

        logger.debug(f'Grabbed item: {item}')
        return item

    async def find_items(
        self, processed: bool, min_age_in_seconds: Optional[int] = None, expired: Optional[bool] = None
    ) -> List:
        # TODO: Add registered payload types to spec
        spec: Dict[str, Any] = {}
        if not processed:
            spec['processed_by'] = None
            spec['processed_ts'] = None

        if min_age_in_seconds is not None:
            latest_created = datetime.utcnow() + timedelta(seconds=min_age_in_seconds)
            spec['created_ts'] = {'$lt': latest_created}

        if expired is not None:
            now = datetime.utcnow()
            if expired:
                spec['expires_at'] = {'$lt': now}
            else:
                spec['expires_at'] = {'$gt': now}

        # to_list needs length, 100 seems like a good start
        # TODO: Investigate if this can be a generator?
        logger.debug(f'spec: {spec}')
        return [doc for doc in await self.collection.find(spec).to_list(length=100)]

    async def remove_item(self, item_id: Union[str, ObjectId]) -> bool:
        """
        Remove a document in the db given the _id.

        :param item_id: document id
        """
        if isinstance(item_id, str):
            item_id = ObjectId(item_id)
        spec = {
            '_id': item_id,
        }
        result = await self.collection.delete_one(spec)
        return result.acknowledged

    async def replace_item(self, old_item: QueueItem, new_item: QueueItem) -> bool:
        if old_item.item_id != new_item.item_id:
            logger.warning(f'Can not replace items with different item_id')
            logger.debug(f'old_item: {old_item}')
            logger.debug(f'new_item: {new_item}')
            return False

        update_result = await self.collection.replace_one(old_item.to_dict(), new_item.to_dict(), upsert=True)
        if not update_result.acknowledged or update_result.modified_count != 1:
            logger.debug(f'Saving of item failed: {update_result.raw_result}')
            return False
        return True
