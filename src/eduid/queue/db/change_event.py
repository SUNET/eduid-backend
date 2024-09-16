from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

__author__ = "lundberg"


class OperationType(Enum):
    # XXX: Database operations only available in MongoDB >=4
    INSERT = "insert"
    DELETE = "delete"
    REPLACE = "replace"
    UPDATE = "update"
    DROP = "drop"
    RENAME = "rename"
    DROPDATABASE = "dropDatabase"
    INVALIDATE = "invalidate"


@dataclass
class ResumeToken:
    data: str | bytes


@dataclass
class NS:
    db: str
    coll: str


@dataclass
class DocumentKey:
    id: str


@dataclass
class UpdateDescription:
    updated_fields: dict[str, Any] | None
    removed_fields: list[str] | None


@dataclass(frozen=True)
class ChangeEvent:
    """
    https://docs.mongodb.com/manual/reference/change-events/
    """

    id: ResumeToken
    operation_type: OperationType
    ns: NS
    document_key: DocumentKey
    full_document: dict[str, Any] | None = None
    to: NS | None = None
    update_description: UpdateDescription | None = None
    # Available in MongoDB >=4
    # clusterTime
    # txnNumber
    # lsid

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ChangeEvent:
        data = dict(data)
        to = None
        update_description = None
        if data.get("to"):
            to_data = data["to"]
            to = NS(db=to_data["db"], coll=to_data["coll"])
        if data.get("updateDescription"):
            updated_data = data["updateDescription"]
            update_description = UpdateDescription(
                updated_fields=updated_data.get("updatedFields"), removed_fields=updated_data.get("removedFields")
            )
        return cls(
            id=ResumeToken(data=data["_id"]["_data"]),
            operation_type=OperationType(data["operationType"]),
            ns=NS(db=data["ns"]["db"], coll=data["ns"]["coll"]),
            document_key=DocumentKey(id=data["documentKey"]["_id"]),
            full_document=data.get("fullDocument"),
            to=to,
            update_description=update_description,
        )
