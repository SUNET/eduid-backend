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
from typing import Union

from bson import ObjectId

from eduid_userdb.db import BaseDB
from eduid_userdb.exceptions import MultipleDocumentsReturned
from eduid_userdb.message import Message

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class MessageDB(BaseDB):
    def __init__(self, db_uri, db_name='eduid_message', collection='messages'):
        super().__init__(db_uri, db_name, collection=collection)
        # Remove messages older than discard_at datetime
        indexes = {
            'auto-discard-messages': {'key': [('discard_at', 1)], 'expireAfterSeconds': 0},
        }
        self.setup_indexes(indexes)

    def get_message_by_id(self, message_id: Union[str, ObjectId], raise_on_missing=True) -> Message:
        if isinstance(message_id, str):
            message_id = ObjectId(message_id)
        docs = self._get_documents_by_filter({'_id': message_id}, raise_on_missing=raise_on_missing)
        if len(docs) > 1:
            raise MultipleDocumentsReturned(f'Multiple matching messages for _id={message_id}')
        return Message.from_dict(docs[0])

    def save(self, message: Message) -> bool:
        test_doc = {'_id': message.message_id}
        res = self._coll.replace_one(test_doc, message.to_dict(), upsert=True)
        # TODO: Check result for fail/success
        return True
