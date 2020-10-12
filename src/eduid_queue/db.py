# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Union

from bson import ObjectId
from eduid_userdb import MongoDB
from eduid_userdb.exceptions import PayloadNotRegistered
from eduid_userdb.q import QueueItem
from eduid_userdb.q.db import QueueDB
from motor import motor_asyncio
from pymongo.results import UpdateResult

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class OperationType(Enum):
    # XXX: Database operations only available in MongoDB >=4
    INSERT = 'insert'
    DELETE = 'delete'
    REPLACE = 'replace'
    UPDATE = 'update'
    DROP = 'drop'
    RENAME = 'rename'
    DROPDATABASE = 'dropDatabase'
    INVALIDATE = 'invalidate'


@dataclass
class ResumeToken:
    data: Union[str, bytes]


@dataclass
class NS:
    db: str
    coll: str


@dataclass
class DocumentKey:
    id: str


@dataclass
class UpdateDescription:
    updated_fields: Optional[Dict[str, Any]]
    removed_fields: Optional[List[str]]


@dataclass(frozen=True)
class ChangeEvent:
    """
    https://docs.mongodb.com/manual/reference/change-events/
    """

    id: ResumeToken
    operation_type: OperationType
    ns: NS
    document_key: DocumentKey
    full_document: Optional[Dict[str, Any]] = None
    to: Optional[NS] = None
    update_description: Optional[UpdateDescription] = None
    # Available in MongoDB >=4
    # clusterTime
    # txnNumber
    # lsid

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ChangeEvent:
        data = dict(data)
        to = None
        update_description = None
        if data.get('to'):
            to_data = data['to']
            to = NS(db=to_data['db'], coll=to_data['coll'])
        if data.get('updateDescription'):
            updated_data = data['updateDescription']
            update_description = UpdateDescription(
                updated_fields=updated_data.get('updatedFields'), removed_fields=updated_data.get('removedFields')
            )
        return cls(
            id=ResumeToken(data=data['_id']['_data']),
            operation_type=OperationType(data['operationType']),
            ns=NS(db=data['ns']['db'], coll=data['ns']['coll']),
            document_key=DocumentKey(id=data['documentKey']['_id']),
            full_document=data.get('fullDocument'),
            to=to,
            update_description=update_description,
        )


class AsyncQueueDB(QueueDB):
    def __init__(self, db_uri: str, collection: str, db_name: str = 'eduid_queue', connection_factory=None):
        super().__init__(db_uri, collection=collection, db_name=db_name)

        # Re-initialize database and collection so we use connection_factory is set
        self._db = MongoDB(db_uri, db_name=db_name, connection_factory=connection_factory)
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
