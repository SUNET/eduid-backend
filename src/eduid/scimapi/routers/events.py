from datetime import timedelta

from fastapi import Response

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.scim_base import SCIMResourceType
from eduid.scimapi.api_router import APIRouter
from eduid.scimapi.context_request import ScimApiContext, ScimApiRoute
from eduid.scimapi.exceptions import BadRequest, ErrorDetail, NotFound
from eduid.scimapi.models.event import EventCreateRequest, EventResponse
from eduid.scimapi.routers.utils.events import db_event_to_response, get_scim_referenced
from eduid.userdb.scimapi import ScimApiEvent, ScimApiEventResource

__author__ = "lundberg"


events_router = APIRouter(
    route_class=ScimApiRoute,
    prefix="/Events",
    responses={
        400: {"description": "Bad request", "model": ErrorDetail},
        404: {"description": "Not found", "model": ErrorDetail},
        500: {"description": "Internal server error", "model": ErrorDetail},
    },
)


@events_router.get("/{scim_id}", response_model=EventResponse, response_model_exclude_none=True)
async def on_get(req: ContextRequest, resp: Response, scim_id: str | None = None) -> EventResponse:
    if scim_id is None:
        raise BadRequest(detail="Not implemented")
    req.app.context.logger.info(f"Fetching event {scim_id}")
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.eventdb is not None  # please mypy
    db_event = req.context.eventdb.get_event_by_scim_id(scim_id)
    if not db_event:
        raise NotFound(detail="Event not found")
    return db_event_to_response(req, resp, db_event)


@events_router.post("/", response_model=EventResponse, response_model_exclude_none=True)
async def on_post(req: ContextRequest, resp: Response, create_request: EventCreateRequest) -> EventResponse:
    """
    POST /Events  HTTP/1.1
    Host: example.com
    Accept: application/scim+json
    Content-Type: application/scim+json
    Authorization: Bearer h480djs93hd8
    Content-Length: ...

    {
        'schemas': ['https://scim.eduid.se/schema/nutid/event/core-v1',
                    'https://scim.eduid.se/schema/nutid/event/v1'],
        'https://scim.eduid.se/schema/nutid/event/v1': {
            'ref': {'resourceType': 'User',
                    'id': '199745a8-a4f5-46b9-9ae9-531da967bfb1',
                    'externalId': 'test@example.org'
                    },
            'data': {'create_test': True},
            'expiresAt': '2021-02-23T14:36:15+00:00',
            'level': 'debug',
            'source': 'eduid.se',
            'timestamp': '2021-02-18T14:36:15+00:00'
            }
    }
    """
    req.app.context.logger.info("Creating event")
    req.app.context.logger.debug(create_request)

    # TODO: Instead of checking input here we should use dump_only for the fields in the schema
    if create_request.nutid_event_v1.source:
        raise BadRequest(detail="source is read-only")
    if create_request.nutid_event_v1.expires_at:
        raise BadRequest(detail="expiresAt is read-only")
    if create_request.nutid_event_v1.resource.external_id:
        raise BadRequest(detail="resource.externalId is read-only")
    if create_request.nutid_event_v1.resource.location:
        raise BadRequest(detail="resource.location is read-only")

    # TODO: This check should move to schema validation
    if create_request.nutid_event_v1.timestamp:
        earliest_allowed = utc_now() - timedelta(days=1)
        if create_request.nutid_event_v1.timestamp < earliest_allowed:
            raise BadRequest(detail="timestamp is too old")

    referenced = get_scim_referenced(req, create_request.nutid_event_v1.resource)
    if not referenced:
        raise BadRequest(detail="referenced object not found")

    _timestamp = utc_now()
    if create_request.nutid_event_v1.timestamp:
        _timestamp = create_request.nutid_event_v1.timestamp
    _expires_at = utc_now() + timedelta(days=1)

    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.data_owner is not None  # please mypy
    assert req.context.eventdb is not None  # please mypy

    event = ScimApiEvent(
        resource=ScimApiEventResource(
            resource_type=create_request.nutid_event_v1.resource.resource_type,
            version=create_request.nutid_event_v1.resource.version,
            last_modified=create_request.nutid_event_v1.resource.last_modified,
            scim_id=referenced.scim_id,
            external_id=referenced.external_id,
        ),
        level=create_request.nutid_event_v1.level,
        source=req.context.data_owner,
        data=create_request.nutid_event_v1.data,
        expires_at=_expires_at,
        timestamp=_timestamp,
    )
    req.context.eventdb.save(event)

    # Send notification
    message = req.app.context.notification_relay.format_message(
        version=1, data={"location": req.app.context.resource_url(SCIMResourceType.EVENT, event.scim_id)}
    )

    req.app.context.notification_relay.notify(
        data_owner=req.context.data_owner, message=message, context=req.app.context
    )

    return db_event_to_response(req, resp, event)
