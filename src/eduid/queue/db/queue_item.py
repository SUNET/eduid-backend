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

from collections import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, Optional

from bson import ObjectId

from eduid.queue.db.payload import Payload, RawPayload

__author__ = 'lundberg'


@dataclass(frozen=True)
class Status:
    success: bool
    retry: bool = False
    message: Optional[str] = None


@dataclass(frozen=True)
class SenderInfo:
    hostname: str
    node_id: str  # Should be something like application@system_hostname ex. scimapi@apps-lla-3

    @classmethod
    def from_dict(cls, data: Mapping):
        data = dict(data)
        return cls(**data)


@dataclass(frozen=True)
class QueueItem:
    version: int
    expires_at: datetime
    discard_at: datetime
    sender_info: SenderInfo
    payload_type: str
    payload: Payload
    item_id: ObjectId = field(default_factory=ObjectId)
    created_ts: datetime = field(default_factory=datetime.utcnow)
    processed_by: Optional[str] = None
    processed_ts: Optional[datetime] = None
    retries: int = 0

    def to_dict(self) -> Dict:
        res = asdict(self)
        res['_id'] = res.pop('item_id',)
        res['payload'] = self.payload.to_dict()
        return res

    @classmethod
    def from_dict(cls, data: Mapping):
        data = dict(data)
        item_id = data.pop('_id')
        processed_by = data.pop('processed_by', None)
        processed_ts = data.pop('processed_ts', None)
        sender_info = SenderInfo.from_dict(data['sender_info'])
        payload = RawPayload.from_dict(data['payload'])
        return cls(
            item_id=item_id,
            payload_type=data['payload_type'],
            version=data['version'],
            expires_at=data['expires_at'],
            discard_at=data['discard_at'],
            sender_info=sender_info,
            payload=payload,
            processed_by=processed_by,
            processed_ts=processed_ts,
        )
