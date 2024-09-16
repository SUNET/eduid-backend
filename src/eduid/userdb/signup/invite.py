from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from bson import ObjectId

from eduid.userdb.db import TUserDbDocument

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
    expires_at: datetime


@dataclass(frozen=True)
class Invite(_InviteRequired):
    invite_id: ObjectId = field(default_factory=ObjectId)
    given_name: str | None = field(default=None)
    surname: str | None = field(default=None)
    mail_addresses: list[InviteMailAddress] = field(default_factory=list)
    phone_numbers: list[InvitePhoneNumber] = field(default_factory=list)
    nin: str | None = field(default=None)
    preferred_language: str = field(default="sv")
    finish_url: str | None = field(default=None)
    completed_ts: datetime | None = field(default=None)
    created_ts: datetime = field(default_factory=datetime.utcnow)
    modified_ts: datetime | None = field(default=None)

    def get_primary_mail_address(self) -> str | None:
        # there can be only one primary mail address set
        primary_mail_address = [item.email for item in self.mail_addresses if item.primary is True]
        if not primary_mail_address:
            return None
        return primary_mail_address[0]

    def to_dict(self) -> TUserDbDocument:
        data = asdict(self)
        data["_id"] = data.pop("invite_id")
        data["invite_type"] = InviteType(data["invite_type"]).value
        return TUserDbDocument(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Invite:
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
        # backwards compatibility
        if "display_name" in data:
            del data["display_name"]
        return cls(**data)
