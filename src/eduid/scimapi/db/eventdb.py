from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Type
from uuid import UUID, uuid4

from bson import ObjectId

from eduid.common.utils import urlappend
from eduid.scimapi.db.basedb import ScimApiBaseDB
from eduid.scimapi.db.common import ScimApiResourceBase
from eduid.scimapi.models.scimbase import SCIMResourceType
from eduid.userdb.util import utc_now

if TYPE_CHECKING:
    from eduid.scimapi.context import Context

logger = logging.getLogger(__name__)


@dataclass
class ScimApiEventResource:
    resource_type: SCIMResourceType
    scim_id: UUID
    external_id: Optional[str]
    version: ObjectId
    last_modified: datetime

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['scim_id'] = str(self.scim_id)
        data['resource_type'] = self.resource_type.value
        return data

    @classmethod
    def from_dict(cls: Type[ScimApiEventResource], data: Mapping[str, Any]) -> ScimApiEventResource:
        _data = dict(data)
        _data['resource_type'] = SCIMResourceType(_data['resource_type'])
        _data['scim_id'] = UUID(_data['scim_id'])
        return cls(**_data)


class EventLevel(Enum):
    DEBUG = 'debug'
    INFO = 'info'
    WARNING = 'warning'
    ERROR = 'error'


class EventStatus(Enum):
    CREATED = 'CREATED'
    UPDATED = 'UPDATED'
    DELETED = 'DELETED'


@dataclass
class _ScimApiEventRequired:
    resource: ScimApiEventResource
    level: EventLevel
    source: str
    data: Dict[str, Any]
    expires_at: datetime
    timestamp: datetime


@dataclass
class ScimApiEvent(ScimApiResourceBase, _ScimApiEventRequired):
    db_id: ObjectId = field(default_factory=lambda: ObjectId())  # mongodb document _id

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['_id'] = data.pop('db_id')
        data['level'] = self.level.value
        data['scim_id'] = str(self.scim_id)
        data['resource'] = self.resource.to_dict()
        return data

    @classmethod
    def from_dict(cls: Type[ScimApiEvent], data: Mapping[str, Any]) -> ScimApiEvent:
        _data = dict(data)
        if '_id' in _data:
            _data['db_id'] = _data.pop('_id')
        _data['level'] = EventLevel(_data['level'])
        _data['scim_id'] = UUID(_data['scim_id'])
        _data['resource'] = ScimApiEventResource.from_dict(_data['resource'])
        return cls(**_data)


class ScimApiEventDB(ScimApiBaseDB):
    def __init__(self, db_uri: str, collection: str, db_name='eduid_scimapi'):
        super().__init__(db_uri, db_name, collection=collection)
        indexes = {
            # Remove messages older than expires_at datetime
            'auto-discard': {'key': [('expires_at', 1)], 'expireAfterSeconds': 0},
            # Ensure unique scim_id
            'unique-scimid': {'key': [('scim_id', 1)], 'unique': True},
        }
        self.setup_indexes(indexes)

    def save(self, event: ScimApiEvent) -> bool:
        """ Save a new event to the database. Events are never expected to be modified. """
        event_dict = event.to_dict()

        result = self._coll.insert_one(event_dict)
        logger.debug(f'{self} Inserted event {event} in {self._coll_name}')
        import pprint

        extra_debug = pprint.pformat(event_dict, width=120)
        logger.debug(f'Extra debug:\n{extra_debug}')

        return result.acknowledged

    def get_events_by_resource(
        self, resource_type: SCIMResourceType, scim_id: Optional[UUID] = None, external_id: Optional[str] = None
    ) -> List[ScimApiEvent]:
        filter = {
            'resource.resource_type': resource_type.value,
        }
        if scim_id is not None:
            filter['resource.scim_id'] = str(scim_id)
        if external_id is not None:
            filter['resource.external_id'] = external_id

        docs = self._get_documents_by_filter(filter)
        if docs:
            return [ScimApiEvent.from_dict(this) for this in docs]
        return []

    def get_event_by_scim_id(self, scim_id: str) -> Optional[ScimApiEvent]:
        doc = self._get_document_by_attr('scim_id', scim_id)
        if not doc:
            return None
        return ScimApiEvent.from_dict(doc)


def add_api_event(
    data_owner: str,
    context: 'Context',
    db_obj: ScimApiResourceBase,
    resource_type: SCIMResourceType,
    level: EventLevel,
    status: EventStatus,
    message: str,
) -> None:
    """ Add an event with source=this-API. """
    _now = utc_now()
    _expires_at = _now + timedelta(days=1)
    _event = ScimApiEvent(
        scim_id=uuid4(),
        resource=ScimApiEventResource(
            resource_type=resource_type,
            scim_id=db_obj.scim_id,
            external_id=db_obj.external_id,
            version=db_obj.version,
            last_modified=db_obj.last_modified,
        ),
        timestamp=_now,
        expires_at=_expires_at,
        source='eduID SCIM API',
        level=level,
        data={'v': 1, 'status': status.value, 'message': message},
    )
    event_db = context.get_eventdb(data_owner=data_owner)
    assert event_db  # please mypy
    event_db.save(_event)

    # Send notification
    event_location = urlappend(context.base_url, f'Events/{_event.scim_id}')
    message = context.notification_relay.format_message(version=1, data={'location': event_location})
    context.notification_relay.notify(data_owner=data_owner, message=message)

    return None
