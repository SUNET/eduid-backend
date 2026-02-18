from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from bson import ObjectId

from eduid.common.models.scim_base import SCIMResourceType
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.scimapi.basedb import ScimApiBaseDB
from eduid.userdb.scimapi.common import ScimApiResourceBase

logger = logging.getLogger(__name__)


@dataclass
class ScimApiEventResource:
    resource_type: SCIMResourceType
    scim_id: UUID
    external_id: str | None
    version: ObjectId
    last_modified: datetime

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["scim_id"] = str(self.scim_id)
        data["resource_type"] = self.resource_type.value
        return data

    @classmethod
    def from_dict(cls: type[ScimApiEventResource], data: Mapping[str, Any]) -> ScimApiEventResource:
        _data = dict(data)
        _data["resource_type"] = SCIMResourceType(_data["resource_type"])
        _data["scim_id"] = UUID(_data["scim_id"])
        return cls(**_data)


class EventLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class EventStatus(Enum):
    CREATED = "CREATED"
    UPDATED = "UPDATED"
    DELETED = "DELETED"


@dataclass
class _ScimApiEventRequired:
    resource: ScimApiEventResource
    level: EventLevel
    source: str
    data: dict[str, Any]
    expires_at: datetime
    timestamp: datetime


@dataclass
class ScimApiEvent(ScimApiResourceBase, _ScimApiEventRequired):
    db_id: ObjectId = field(default_factory=ObjectId)  # mongodb document _id

    def to_dict(self) -> TUserDbDocument:
        data = asdict(self)
        data["_id"] = data.pop("db_id")
        data["level"] = self.level.value
        data["scim_id"] = str(self.scim_id)
        data["resource"] = self.resource.to_dict()
        return TUserDbDocument(data)

    @classmethod
    def from_dict(cls: type[ScimApiEvent], data: Mapping[str, Any]) -> ScimApiEvent:
        _data = dict(data)
        if "_id" in _data:
            _data["db_id"] = _data.pop("_id")
        _data["level"] = EventLevel(_data["level"])
        _data["scim_id"] = UUID(_data["scim_id"])
        _data["resource"] = ScimApiEventResource.from_dict(_data["resource"])
        return cls(**_data)


class ScimApiEventDB(ScimApiBaseDB):
    def __init__(self, db_uri: str, collection: str, db_name: str = "eduid_scimapi") -> None:
        super().__init__(db_uri, db_name, collection=collection)
        indexes = {
            # Remove messages older than expires_at datetime
            "auto-discard": {"key": [("expires_at", 1)], "expireAfterSeconds": 0},
            # Ensure unique scim_id
            "unique-scimid": {"key": [("scim_id", 1)], "unique": True},
        }
        self.setup_indexes(indexes)

    def save(self, event: ScimApiEvent) -> bool:
        """Save a new event to the database. Events are never expected to be modified."""
        event_dict = event.to_dict()

        result = self._coll.insert_one(event_dict)
        logger.debug(f"{self} Inserted event {event} in {self._coll_name}")
        import pprint

        extra_debug = pprint.pformat(event_dict, width=120)
        logger.debug(f"Extra debug:\n{extra_debug}")

        return result.acknowledged

    def get_events_by_resource(
        self, resource_type: SCIMResourceType, scim_id: UUID | None = None, external_id: str | None = None
    ) -> list[ScimApiEvent]:
        spec = {
            "resource.resource_type": resource_type.value,
        }
        if scim_id is not None:
            spec["resource.scim_id"] = str(scim_id)
        if external_id is not None:
            spec["resource.external_id"] = external_id

        docs = self._get_documents_by_filter(spec)
        if docs:
            return [ScimApiEvent.from_dict(this) for this in docs]
        return []

    def get_event_by_scim_id(self, scim_id: str) -> ScimApiEvent | None:
        doc = self._get_document_by_attr("scim_id", scim_id)
        if not doc:
            return None
        return ScimApiEvent.from_dict(doc)
