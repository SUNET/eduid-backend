import logging
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from bson import ObjectId
from pymongo.results import UpdateResult

from eduid.common.misc.timeutil import utc_now
from eduid.queue.db import Payload, QueueItem
from eduid.queue.db.client import QueuePayloadMixin
from eduid.queue.exceptions import PayloadNotRegistered
from eduid.userdb.db.async_db import AsyncBaseDB

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class AsyncQueueDB(AsyncBaseDB, QueuePayloadMixin):
    def __init__(self, db_uri: str, collection: str, db_name: str = "eduid_queue") -> None:
        super().__init__(db_uri, collection=collection, db_name=db_name)

        self.handlers: dict[str, type[Payload]] = {}

    @classmethod
    async def create(cls, db_uri: str, collection: str, db_name: str = "eduid_queue") -> "AsyncQueueDB":
        # Remove messages older than discard_at datetime
        indexes = {
            "auto-discard": {"key": [("discard_at", 1)], "expireAfterSeconds": 0},
        }
        instance = cls(db_uri=db_uri, collection=collection, db_name=db_name)
        await instance.setup_indexes(indexes)
        return instance

    def parse_queue_item(self, doc: Mapping, parse_payload: bool = True) -> QueueItem:
        item = QueueItem.from_dict(doc)
        if parse_payload is False:
            # Return the item with the generic RawPayload
            return item
        return replace(item, payload=self._load_payload(item))

    async def grab_item(self, item_id: str | ObjectId, worker_name: str, regrab: bool = False) -> QueueItem | None:
        """
        :param item_id: document id
        :param worker_name: current workers name
        :param regrab: If True, try to grab an already processed item for reprocessing
        :return: queue item
        """
        logger.debug(f"Grabbing item for {worker_name}")

        if isinstance(item_id, str):
            item_id = ObjectId(item_id)

        spec: dict[str, Any] = {
            "_id": item_id,
        }

        if not regrab:
            # Only try to grab previously untouched items
            spec["processed_by"] = None
            spec["processed_ts"] = None

        # Get item
        doc = await self.collection.find_one(spec)
        if not doc:
            return None

        if regrab:
            # Only replace items that still has the previous worker name and ts
            spec["processed_by"] = doc["processed_by"]
            spec["processed_ts"] = doc["processed_ts"]

        # Update item with current worker name and ts
        mutable_doc = dict(doc)
        mutable_doc["processed_by"] = worker_name
        mutable_doc["processed_ts"] = datetime.now(tz=UTC)

        try:
            # Try to parse the queue item to only grab items that are registered with the current db
            item = self.parse_queue_item(mutable_doc, parse_payload=True)
        except PayloadNotRegistered as e:
            logger.debug(e)
            return None

        update_result: UpdateResult = await self.collection.replace_one(spec, mutable_doc)
        logger.debug(f"result: {update_result.raw_result}")
        if not update_result.acknowledged or update_result.modified_count != 1:
            logger.debug(f"Grabbing of item failed: {update_result.raw_result}")
            return None

        logger.debug(f"Grabbed item: {item}")
        return item

    async def find_items(
        self, processed: bool, min_age_in_seconds: int | None = None, expired: bool | None = None
    ) -> list:
        # TODO: Add registered payload types to spec
        spec: dict[str, Any] = {}
        if not processed:
            spec["processed_by"] = None
            spec["processed_ts"] = None

        if min_age_in_seconds is not None:
            latest_created = utc_now() + timedelta(seconds=min_age_in_seconds)
            spec["created_ts"] = {"$lt": latest_created}

        if expired is not None:
            now = utc_now()
            if expired:
                spec["expires_at"] = {"$lt": now}
            else:
                spec["expires_at"] = {"$gt": now}

        # to_list needs length, 100 seems like a good start
        # TODO: Investigate if this can be a generator?
        logger.debug(f"spec: {spec}")
        return await self.collection.find(spec).to_list(length=100)

    async def remove_item(self, item_id: str | ObjectId) -> bool:
        """
        Remove a document in the db given the _id.

        :param item_id: document id
        """
        if isinstance(item_id, str):
            item_id = ObjectId(item_id)
        spec = {
            "_id": item_id,
        }
        result = await self.collection.delete_one(spec)
        return result.acknowledged

    async def replace_item(self, old_item: QueueItem, new_item: QueueItem) -> bool:
        if old_item.item_id != new_item.item_id:
            logger.warning("Can not replace items with different item_id")
            logger.debug(f"old_item: {old_item}")
            logger.debug(f"new_item: {new_item}")
            return False

        update_result = await self.collection.replace_one({"_id": old_item.item_id}, new_item.to_dict(), upsert=True)
        if not update_result.acknowledged or update_result.modified_count != 1:
            logger.debug(f"Saving of item failed: {update_result.raw_result}")
            return False
        return True

    async def save(self, item: QueueItem) -> bool:
        test_doc = {"_id": item.item_id}
        res = await self._coll.replace_one(test_doc, item.to_dict(), upsert=True)
        return res.acknowledged
