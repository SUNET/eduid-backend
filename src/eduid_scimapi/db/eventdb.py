import logging
import typing
from datetime import timedelta
from typing import List
from uuid import UUID, uuid4

from eduid_userdb.util import utc_now

from eduid_scimapi.db.basedb import ScimApiBaseDB
from eduid_scimapi.db.common import EventLevel, ScimApiEvent

if typing.TYPE_CHECKING:
    from eduid_scimapi.db.userdb import ScimApiUser


logger = logging.getLogger(__name__)


class ScimApiEventDB(ScimApiBaseDB):
    def __init__(self, db_uri: str, collection: str, db_name='eduid_scimapi'):
        super().__init__(db_uri, db_name, collection=collection)
        # TODO: Create index to ensure unique event_id

    def save(self, event: ScimApiEvent) -> bool:
        """ Save a new event to the database. Events are never expected to be modified. """
        event_dict = event.to_dict()

        result = self._coll.insert_one(event_dict)
        logger.debug(f'{self} Inserted event {event} in {self._coll_name}')
        import pprint

        extra_debug = pprint.pformat(event_dict, width=120)
        logger.debug(f'Extra debug:\n{extra_debug}')

        return result.acknowledged

    def get_events_by_scim_user_id(self, scim_user_id: UUID) -> List[ScimApiEvent]:
        docs = self._get_documents_by_attr('scim_user_id', str(scim_user_id), raise_on_missing=False)
        if docs:
            return [ScimApiEvent.from_dict(this) for this in docs]
        return []

    def get_event_by_scim_id(self, scim_id: str) -> typing.Optional[ScimApiEvent]:
        doc = self._get_document_by_attr('scim_id', scim_id, raise_on_missing=False)
        if not doc:
            return None
        return ScimApiEvent.from_dict(doc)


def add_api_event(
    event_db: ScimApiEventDB, db_user: 'ScimApiUser', level: EventLevel, status: str, message: str
) -> None:
    """ Add an event with source=this-API to a user. """
    _now = utc_now()
    _expires_at = _now + timedelta(days=5)
    _event = ScimApiEvent(
        scim_id=uuid4(),
        scim_user_id=db_user.scim_id,
        scim_user_external_id=db_user.external_id,
        timestamp=_now,
        expires_at=_expires_at,
        source='eduID SCIM API',
        level=level,
        data={'v': 1, 'status': status, 'message': message},
    )
    event_db.save(_event)
    return None
