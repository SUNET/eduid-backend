from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from httpx import Response

from eduid.common.models.scim_base import SCIMResourceType, SCIMSchema
from eduid.common.testing_base import normalised_data
from eduid.common.utils import make_etag
from eduid.scimapi.models.event import EventResponse, NutidEventExtensionV1
from eduid.scimapi.testing import ScimApiTestCase
from eduid.userdb.scimapi import EventLevel, ScimApiEvent


@dataclass
class EventApiResult:
    response: Response
    event: NutidEventExtensionV1
    parsed_response: EventResponse
    request: Mapping | None = None


class TestEventResource(ScimApiTestCase):
    def setUp(self) -> None:
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()
        assert self.eventdb
        self.eventdb._drop_whole_collection()

    def _create_event(self, event: dict[str, Any], expect_success: bool = True) -> EventApiResult:
        req = {
            "schemas": [SCIMSchema.NUTID_EVENT_CORE_V1.value, SCIMSchema.NUTID_EVENT_V1.value],
            SCIMSchema.NUTID_EVENT_V1.value: event,
        }
        response = self.client.post(url="/Events/", json=req, headers=self.headers)
        if expect_success:
            self._assertResponse(response)
        parsed_response = EventResponse.model_validate_json(response.text)
        return EventApiResult(
            request=req, event=parsed_response.nutid_event_v1, response=response, parsed_response=parsed_response
        )

    def _fetch_event(self, event_id: UUID) -> EventApiResult:
        response = self.client.get(url=f"/Events/{str(event_id)}", headers=self.headers)
        self._assertResponse(response)
        parsed_response = EventResponse.model_validate_json(response.text)
        return EventApiResult(event=parsed_response.nutid_event_v1, response=response, parsed_response=parsed_response)

    def _assertEventUpdateSuccess(self, req: Mapping, response: Response, event: ScimApiEvent) -> None:
        """Function to validate successful responses to SCIM calls that update a event according to a request."""

        if response.json().get("schemas") == [SCIMSchema.ERROR.value]:
            self.fail(f"Got SCIM error parsed_response ({response.status_code}):\n{response.json()}")

        expected_schemas = req.get("schemas", [SCIMSchema.NUTID_EVENT_CORE_V1.value])
        if (
            SCIMSchema.NUTID_EVENT_V1.value in response.json()
            and SCIMSchema.NUTID_EVENT_V1.value not in expected_schemas
        ):
            # The API can always add this extension to the parsed_response, even if it was not in the request
            expected_schemas += [SCIMSchema.NUTID_EVENT_V1.value]

        self._assertScimResponseProperties(response, resource=event, expected_schemas=expected_schemas)

    def test_create_event(self) -> None:
        user = self.add_user(identifier=str(uuid4()), external_id="test@example.org")
        event = {
            "resource": {
                "resourceType": SCIMResourceType.USER.value,
                "id": str(user.scim_id),
                "version": make_etag(user.version),
                "lastModified": str(user.last_modified),
            },
            "level": EventLevel.DEBUG.value,
            "data": {"create_test": True},
        }
        result = self._create_event(event=event)

        # check that the create resulted in an event in the database
        assert self.eventdb
        events = self.eventdb.get_events_by_resource(SCIMResourceType.USER, scim_id=user.scim_id)
        assert len(events) == 1
        db_event = events[0]
        # Verify what went into the database
        assert db_event.resource.resource_type == SCIMResourceType.USER
        assert db_event.resource.scim_id == user.scim_id
        assert db_event.resource.version == user.version
        assert db_event.resource.last_modified == user.last_modified
        assert db_event.resource.external_id == user.external_id
        assert db_event.data == event["data"]
        # Verify what is returned in the parsed_response
        assert result.parsed_response.id == db_event.scim_id
        assert result.request
        self._assertEventUpdateSuccess(req=result.request, response=result.response, event=db_event)

    def test_create_and_fetch_event(self) -> None:
        user = self.add_user(identifier=str(uuid4()), external_id="test@example.org")
        event = {
            "resource": {
                "resourceType": SCIMResourceType.USER.value,
                "id": str(user.scim_id),
                "version": make_etag(user.version),
                "lastModified": user.last_modified.isoformat(),
            },
            "level": EventLevel.DEBUG.value,
            "data": {"create_fetch_test": True},
        }
        created = self._create_event(event=event)

        # check that the creation resulted in an event in the database
        assert self.eventdb
        events = self.eventdb.get_events_by_resource(SCIMResourceType.USER, scim_id=user.scim_id)
        assert len(events) == 1
        db_event = events[0]

        # Now fetch the event using SCIM
        fetched = self._fetch_event(created.parsed_response.id)
        assert fetched.parsed_response.id == db_event.scim_id

        # Verify that create and fetch returned the same data.
        # Compare as dict first because the output is easier to read.
        assert normalised_data(created.event.model_dump(exclude_none=True)) == normalised_data(
            fetched.event.model_dump(exclude_none=True)
        )

        # For once, verify the actual SCIM message format too
        expected = {
            "schemas": [
                "https://scim.eduid.se/schema/nutid/event/core-v1",
                "https://scim.eduid.se/schema/nutid/event/v1",
            ],
            "id": str(db_event.scim_id),
            "meta": {
                "created": db_event.created.isoformat(),
                "lastModified": db_event.last_modified.isoformat(),
                "location": f"http://localhost:8000/Events/{db_event.scim_id}",
                "resourceType": "Event",
                "version": make_etag(db_event.version),
            },
            "https://scim.eduid.se/schema/nutid/event/v1": {
                "data": {"create_fetch_test": True},
                "expiresAt": (db_event.timestamp + timedelta(days=1)).isoformat(),
                "level": "debug",
                "source": "eduid.se",
                "timestamp": db_event.timestamp.isoformat(),
                "resource": {
                    "resourceType": "User",
                    "id": str(user.scim_id),
                    "lastModified": user.last_modified.isoformat(),
                    "version": make_etag(user.version),
                    "externalId": user.external_id,
                    "location": f"http://localhost:8000/Users/{user.scim_id}",
                },
            },
        }
        assert fetched.response.json() == expected
