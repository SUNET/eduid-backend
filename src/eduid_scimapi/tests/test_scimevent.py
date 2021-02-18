from dataclasses import dataclass
from typing import Any, Dict
from uuid import UUID, uuid4

from falcon.testing import Result

from eduid_userdb.testing import normalised_data

from eduid_scimapi.db.common import EventLevel
from eduid_scimapi.schemas.event import EventResponse, EventResponseSchema, NutidEventExtensionV1
from eduid_scimapi.schemas.scimbase import SCIMSchema
from eduid_scimapi.testing import ScimApiTestCase


@dataclass
class ApiResult:
    result: Result
    event: NutidEventExtensionV1
    response: EventResponse


class TestInviteResource(ScimApiTestCase):
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
            'userId': str(user.scim_id),
            'userExternalId': user.external_id,
            'level': EventLevel.DEBUG.value,
            'data': {'create_test': True},
        }
        response = self._create_event(event=event)

        # check that the create resulted in an event in the database
        events = self.eventdb.get_events_by_scim_user_id(user.scim_id)
        assert len(events) == 1
        db_event = events[0]
        # Verify what went into the database
        assert db_event.scim_user_external_id == user.external_id
        assert db_event.data == event['data']
        # Verify what is returned in the response
        response_event = response.result.json[SCIMSchema.NUTID_EVENT_V1.value]
        assert response_event['id'] == str(db_event.scim_id)

    def test_create_and_fetch_event(self):
        user = self.add_user(identifier=str(uuid4()), external_id='test@example.org')
        event = {
            'userId': str(user.scim_id),
            'userExternalId': user.external_id,
            'level': EventLevel.DEBUG.value,
            'data': {'create_test': True},
        }
        created = self._create_event(event=event)

        # check that the create resulted in an event in the database
        events = self.eventdb.get_events_by_scim_user_id(user.scim_id)
        assert len(events) == 1
        db_event = events[0]

        # Now fetch the event using SCIM
        fetched = self._fetch_event(created.event.id)
        assert fetched.event.id == db_event.scim_id

        # Verify that create and fetch returned the same data
        assert created.event == fetched.event
