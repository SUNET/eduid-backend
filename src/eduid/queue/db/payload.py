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
from abc import ABC
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, Mapping, TypeVar

__author__ = 'lundberg'

TPayload = TypeVar('TPayload', bound='Payload')


@dataclass
class Payload(ABC):
    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        raise NotImplementedError()

    @classmethod
    def get_type(cls):
        return cls.__name__


@dataclass
class RawPayload(Payload):
    data: Dict

    def to_dict(self):
        return self.data

    @classmethod
    def from_dict(cls, data: Mapping):
        data = dict(data)  # Do not change caller data
        return cls(data=data)


@dataclass
class TestPayload(Payload):
    message: str
    created_ts: datetime = field(default_factory=datetime.utcnow)
    version: int = 1

    @classmethod
    def from_dict(cls, data: Mapping):
        data = dict(data)  # Do not change caller data
        return cls(**data)
