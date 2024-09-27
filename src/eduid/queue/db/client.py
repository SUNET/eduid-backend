import logging
from dataclasses import replace
from typing import Any

from bson import ObjectId

from eduid.queue.db.payload import Payload
from eduid.queue.db.queue_item import QueueItem
from eduid.queue.exceptions import PayloadNotRegistered
from eduid.userdb.db import BaseDB
from eduid.userdb.exceptions import MultipleDocumentsReturned

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class QueuePayloadMixin:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.handlers: dict[str, type[Payload]] = dict()

    def register_handler(self, payload: type[Payload]) -> None:
        payload_type = payload.get_type()
        if payload_type in self.handlers:
            raise KeyError(f"Payload type '{payload_type}' already registered with {self}")
        logger.info(f"Registered {payload_type} with {self}")
        self.handlers[payload_type] = payload

    def _load_payload(self, item: QueueItem) -> Payload:
        try:
            payload_cls = self.handlers[item.payload_type]
        except KeyError:
            raise PayloadNotRegistered(f"Payload type '{item.payload_type}' not registered with {self}")
        return payload_cls.from_dict(item.payload.to_dict())


class QueueDB(BaseDB, QueuePayloadMixin):
    def __init__(self, db_uri: str, collection: str, db_name: str = "eduid_queue"):
        super().__init__(db_uri=db_uri, db_name=db_name, collection=collection)

        self.handlers: dict[str, type[Payload]] = dict()

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
