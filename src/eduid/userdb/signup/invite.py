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
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Union
from uuid import UUID

from bson import ObjectId

__author__ = "lundberg"


class InviteType(Enum):
    SCIM = "SCIM"


@dataclass(frozen=True)
class InviteReference:
    pass


@dataclass(frozen=True)
class SCIMReference(InviteReference):
    data_owner: str
    scim_id: UUID


@dataclass(frozen=True)
class InviteMailAddress:
    email: str
    primary: bool

    def __post_init__(self):
        # Make sure email is lowercase on init as we had trouble with mixed case
        super().__setattr__("email", self.email.lower())


@dataclass(frozen=True)
class InvitePhoneNumber:
    number: str
    primary: bool


@dataclass(frozen=True)
class _InviteRequired:
    invite_type: InviteType
    invite_reference: InviteReference
    invite_code: str
    inviter_name: str
    send_email: bool


@dataclass(frozen=True)
class Invite(_InviteRequired):
    invite_id: ObjectId = field(default_factory=ObjectId)
    display_name: Optional[str] = field(default=None)
    given_name: Optional[str] = field(default=None)
    surname: Optional[str] = field(default=None)
    mail_addresses: List[InviteMailAddress] = field(default_factory=list)
    phone_numbers: List[InvitePhoneNumber] = field(default_factory=list)
    nin: Optional[str] = field(default=None)
    preferred_language: str = field(default="sv")
    finish_url: Optional[str] = field(default=None)
    completed_ts: Optional[datetime] = field(default=None)
    expires_at: Optional[datetime] = field(default=None)
    created_ts: datetime = field(default_factory=datetime.utcnow)
    modified_ts: Optional[datetime] = field(default=None)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["_id"] = data.pop("invite_id")
        data["invite_type"] = InviteType(data["invite_type"]).value
        return data

    @classmethod
    def from_dict(cls, data: Mapping) -> Invite:
        data = dict(data)
        data["invite_id"] = data.pop("_id")
        data["invite_type"] = InviteType(data["invite_type"])
        if data.get("mail_addresses"):
            data["mail_addresses"] = [InviteMailAddress(**address) for address in data["mail_addresses"]]
        if data.get("phone_numbers"):
            data["phone_numbers"] = [InvitePhoneNumber(**number) for number in data["phone_numbers"]]
        # Load invite specific data
        if data["invite_type"] is InviteType.SCIM:
            data["invite_reference"] = SCIMReference(**data["invite_reference"])
        return cls(**data)
