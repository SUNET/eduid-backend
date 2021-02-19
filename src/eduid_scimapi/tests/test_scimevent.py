from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any, Dict
from uuid import UUID, uuid4

from falcon.testing import Result

from eduid_scimapi.db.common import EventLevel
from eduid_scimapi.resources.base import SCIMResource
from eduid_scimapi.schemas.event import EventResponse, EventResponseSchema, NutidEventExtensionV1
from eduid_scimapi.schemas.scimbase import SCIMResourceType, SCIMSchema
from eduid_scimapi.testing import ScimApiTestCase
from eduid_scimapi.utils import make_etag


@dataclass
class ApiResult:
    result: Result
    event: NutidEventExtensionV1
    response: EventResponse


class TestEventResource(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()

    def tearDown(self):
        super().tearDown()
        self.eventdb._drop_whole_collection()

    def _create_event(self, event: Dict[str, Any], expect_success: bool = True) -> ApiResult:
        req = {'schemas': [SCIMSchema.NUTID_EVENT_V1.value], SCIMSchema.NUTID_EVENT_V1.value: event}
        result = self.client.simulate_post(path='/Events/', body=self.as_json(req), headers=self.headers)
        if expect_success:
            self._assertResponse200(result)
        response: EventResponse = EventResponseSchema().load(result.json)
        return ApiResult(event=response.nutid_event_v1, result=result, response=response)

    def _fetch_event(self, event_id: UUID) -> ApiResult:
        result = self.client.simulate_get(path=f'/Events/{str(event_id)}', headers=self.headers)
        self._assertResponse200(result)
        response: EventResponse = EventResponseSchema().load(result.json)
        return ApiResult(event=response.nutid_event_v1, result=result, response=response)

    def test_create_event(self):
        user = self.add_user(identifier=str(uuid4()), external_id='test@example.org')
        event = {
            'resource': {
                'resourceType': SCIMResourceType.USER.value,
                'id': str(user.scim_id),
                'externalId': user.external_id,
            },
            'level': EventLevel.DEBUG.value,
            'data': {'create_test': True},
        }
        result = self._create_event(event=event)

        # check that the create resulted in an event in the database
        events = self.eventdb.get_events_by_scim_user_id(user.scim_id)
        assert len(events) == 1
        db_event = events[0]
        # Verify what went into the database
        assert db_event.resource.resource_type == SCIMResourceType.USER
        assert db_event.resource.scim_id == user.scim_id
        assert db_event.resource.external_id == user.external_id
        assert db_event.data == event['data']
        # Verify what is returned in the response
        assert result.response.id == db_event.scim_id

    def test_create_and_fetch_event(self):
        user = self.add_user(identifier=str(uuid4()), external_id='test@example.org')
        event = {
            'resource': {
                'resourceType': SCIMResourceType.USER.value,
                'id': str(user.scim_id),
                'externalId': user.external_id,
            },
            'level': EventLevel.DEBUG.value,
            'data': {'create_fetch_test': True},
        }
        created = self._create_event(event=event)

        # check that the create resulted in an event in the database
        events = self.eventdb.get_events_by_scim_user_id(user.scim_id)
        assert len(events) == 1
        db_event = events[0]

        # Now fetch the event using SCIM
        fetched = self._fetch_event(created.response.id)
        assert fetched.response.id == db_event.scim_id

        # Verify that create and fetch returned the same data.
        # Compare as dict first because the output is easier to read.
        assert asdict(created.event) == asdict(fetched.event)
        assert created.event == fetched.event

        # For once, verify the actual SCIM message format too
        expected = {
            'schemas': [
                'https://scim.eduid.se/schema/nutid/event/core-v1',
                'https://scim.eduid.se/schema/nutid/event/v1',
            ],
            'id': str(db_event.scim_id),
            'meta': {
                'created': db_event.created.isoformat(),
                'lastModified': db_event.last_modified.isoformat(),
                'location': f'http://localhost:8000/Events/{db_event.scim_id}',
                'resourceType': 'Event',
                'version': make_etag(db_event.version),
            },
            'https://scim.eduid.se/schema/nutid/event/v1': {
                'data': {'create_fetch_test': True},
                'expiresAt': (db_event.timestamp + timedelta(days=1)).isoformat(),
                'level': 'debug',
                'source': 'eduid.se',
                'timestamp': db_event.timestamp.isoformat(),
                'resource': {
                    'resourceType': 'User',
                    'id': str(user.scim_id),
                    'externalId': user.external_id,
                    'location': f'http://localhost:8000/Users/{user.scim_id}',
                },
            },
        }
        assert fetched.result.json == expected
