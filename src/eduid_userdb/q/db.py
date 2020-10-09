# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 Sunet
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import logging
from dataclasses import replace
from typing import Dict, Mapping, Optional, Type, Union

from bson import ObjectId

from eduid_userdb.db import BaseDB, MongoDB
from eduid_userdb.exceptions import MultipleDocumentsReturned, PayloadNotRegistered
from eduid_userdb.q import Payload
from eduid_userdb.q.payload import RawPayload
from eduid_userdb.q.queue_item import QueueItem

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class QueueDB(BaseDB):
    def __init__(self, db_uri: str, collection: str, db_name: str = 'eduid_queue'):
        super().__init__(db_uri, db_name, collection=collection)
        self.handlers: Dict[str, Type[Payload]] = dict()

        # Remove messages older than discard_at datetime
        indexes = {
            'auto-discard': {'key': [('discard_at', 1)], 'expireAfterSeconds': 0},
        }
        self.setup_indexes(indexes)

    def register_handler(self, payload: Type[Payload]):
        payload_type = payload.get_type()
        if payload_type in self.handlers:
            raise KeyError(f'Payload type \'{payload_type}\' already registered with {self}')
        self.handlers[payload_type] = payload

    def _load_payload(self, item: QueueItem) -> Payload:
        try:
            payload_cls = self.handlers[item.payload_type]
        except KeyError:
            raise PayloadNotRegistered(f'Payload type \'{item.payload_type}\' not registered with {self}')
        return payload_cls.from_dict(item.payload.to_dict())

    def get_item_by_id(
        self, message_id: Union[str, ObjectId], raise_on_missing=True, parse_payload=True
    ) -> Optional[QueueItem]:
        if isinstance(message_id, str):
            message_id = ObjectId(message_id)

        docs = self._get_documents_by_filter({'_id': message_id}, raise_on_missing=raise_on_missing)
        if len(docs) == 0:
            return None
        if len(docs) > 1:
            raise MultipleDocumentsReturned(f'Multiple matching messages for _id={message_id}')

        item = QueueItem.from_dict(docs[0])
        if parse_payload is False:
            # Return the item with the generic RawPayload
            return item
        item = replace(item, payload=self._load_payload(item))
        return item

    def save(self, item: QueueItem) -> bool:
        test_doc = {'_id': item.item_id}
        res = self._coll.replace_one(test_doc, item.to_dict(), upsert=True)
        return res.acknowledged
