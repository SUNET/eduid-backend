import hashlib
import logging
from dataclasses import replace
from typing import Any

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from eduid.queue.db.payload import Payload
from eduid.queue.db.queue_item import QueueItem
from eduid.queue.exceptions import PayloadNotRegistered
from eduid.userdb.db import BaseDB
from eduid.userdb.exceptions import MultipleDocumentsReturned

logger = logging.getLogger(__name__)

__author__ = "lundberg"


def deterministic_item_id(dedup_key: str) -> ObjectId:
    """
    Derive a stable item_id (an ObjectId, 12 bytes) from a deduplication key: the first 12 bytes of its SHA-256.

    Used with QueueDB.save_if_absent to make queueing idempotent. Random ObjectIds are timestamp based, so a
    collision with one is practically impossible.
    """
    return ObjectId(hashlib.sha256(dedup_key.encode("utf-8")).digest()[:12])


class QueuePayloadMixin:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.handlers: dict[str, type[Payload]] = {}

    def register_handler(self, payload: type[Payload]) -> None:
        payload_type = payload.get_type()
        if payload_type in self.handlers:
            raise KeyError(f"Payload type '{payload_type}' already registered with {self}")
        logger.info(f"Registered {payload_type} with {self}")
        self.handlers[payload_type] = payload

    def _load_payload(self, item: QueueItem) -> Payload:
        try:
            payload_cls = self.handlers[item.payload_type]
        except KeyError as e:
            raise PayloadNotRegistered(f"Payload type '{item.payload_type}' not registered with {self}") from e
        return payload_cls.from_dict(item.payload.to_dict())


class QueueDB(BaseDB, QueuePayloadMixin):
    def __init__(self, db_uri: str, collection: str, db_name: str = "eduid_queue") -> None:
        super().__init__(db_uri=db_uri, db_name=db_name, collection=collection)

        self.handlers: dict[str, type[Payload]] = {}

        # Remove messages older than discard_at datetime
        indexes = {
            "auto-discard": {"key": [("discard_at", 1)], "expireAfterSeconds": 0},
        }
        self.setup_indexes(indexes)

    def get_item_by_id(self, message_id: str | ObjectId, parse_payload: bool = True) -> QueueItem | None:
        if isinstance(message_id, str):
            message_id = ObjectId(message_id)

        docs = self._get_documents_by_filter({"_id": message_id})
        if len(docs) == 0:
            return None
        if len(docs) > 1:
            raise MultipleDocumentsReturned(f"Multiple matching messages for _id={message_id}")

        item = QueueItem.from_dict(docs[0])
        if parse_payload is False:
            # Return the item with the generic RawPayload
            return item
        item = replace(item, payload=self._load_payload(item))
        return item

    def save(self, item: QueueItem) -> bool:
        test_doc = {"_id": item.item_id}
        res = self._coll.replace_one(test_doc, item.to_dict(), upsert=True)
        return res.acknowledged

    def save_if_absent(self, item: QueueItem) -> bool:
        """
        Insert the item unless an item with the same item_id already exists. An existing item is never
        overwritten (unlike save), so a processing state is not reset. Together with deterministic_item_id this
        makes queueing idempotent for as long as the first item is still in the collection (until it has been
        handled by a worker and removed, or discarded).

        :returns: True if the item was inserted, False if an item with this item_id already existed
        """
        try:
            self._coll.insert_one(item.to_dict())
        except DuplicateKeyError:
            return False
        return True
