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
from enum import Enum
from typing import Dict, Type

from bson import ObjectId

from eduid_userdb.message.payload import EduidInviteEmail, Payload, TestPayload

__author__ = 'lundberg'


class MessageType(Enum):
    TEST_PAYLOAD = 'test_payload'
    EDUID_INVITE_EMAIL = 'eduid_invite_email'


PAYLOAD_LOADERS: Dict[MessageType, Type[Payload]] = {
    MessageType.TEST_PAYLOAD: TestPayload,
    MessageType.EDUID_INVITE_EMAIL: EduidInviteEmail,
}


@dataclass
class SenderInfo:
    hostname: str
    node_id: str  # Should be something like application@system_hostname ex. scimapi@apps-lla-3

    @classmethod
    def from_dict(cls, data: Mapping):
        data = dict(data)
        return cls(**data)


@dataclass
class Message:
    type: MessageType
    version: int
    expires_at: datetime
    discard_at: datetime
    sender_info: SenderInfo
    payload: Dict
    message_id: ObjectId = field(default_factory=ObjectId)
    created_ts: datetime = field(default_factory=datetime.utcnow)

    def get_payload(self) -> Payload:
        try:
            payload_cls = PAYLOAD_LOADERS[self.type]
            return payload_cls.from_dict(self.payload)
        except KeyError:
            raise NotImplemented(f'Payload of type {self.type} not implemented')

    def to_dict(self) -> Dict:
        res = asdict(self)
        res['_id'] = res.pop('message_id')
        res['type'] = self.type.value
        return res

    @classmethod
    def from_dict(cls, data: Mapping):
        data = dict(data)
        message_id = data.pop('_id')
        message_type = MessageType(data['type'])
        sender_info = SenderInfo.from_dict(data['sender_info'])
        return cls(
            message_id=message_id,
            type=message_type,
            version=data['version'],
            expires_at=data['expires_at'],
            discard_at=data['discard_at'],
            sender_info=sender_info,
            payload=data['payload'],
        )
