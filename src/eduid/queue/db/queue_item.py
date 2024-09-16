from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from bson import ObjectId

from eduid.queue.db.payload import Payload, RawPayload
from eduid.userdb.db import TUserDbDocument

__author__ = "lundberg"


@dataclass(frozen=True)
class Status:
    success: bool
    retry: bool = False
    message: str | None = None


@dataclass(frozen=True)
class SenderInfo:
    hostname: str
    node_id: str  # Should be something like application@system_hostname ex. scimapi@apps-lla-3

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]):
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
    processed_by: str | None = None
    processed_ts: datetime | None = None
    retries: int = 0

    def to_dict(self) -> TUserDbDocument:
        res = asdict(self)
        res["_id"] = res.pop("item_id")
        res["payload"] = self.payload.to_dict()
        return TUserDbDocument(res)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]):
        data = dict(data)
        item_id = data.pop("_id")
        processed_by = data.pop("processed_by", None)
        processed_ts = data.pop("processed_ts", None)
        sender_info = SenderInfo.from_dict(data["sender_info"])
        payload = RawPayload.from_dict(data["payload"])
        return cls(
            item_id=item_id,
            payload_type=data["payload_type"],
            version=data["version"],
            expires_at=data["expires_at"],
            discard_at=data["discard_at"],
            sender_info=sender_info,
            payload=payload,
            processed_by=processed_by,
            processed_ts=processed_ts,
        )
