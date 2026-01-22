from datetime import timedelta
from typing import TYPE_CHECKING
from uuid import uuid4

from fastapi import Response

from eduid.common.config.base import DataOwnerName
from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.models.scim_base import Meta, SCIMResourceType, SCIMSchema, WeakVersion
from eduid.common.utils import make_etag, urlappend
from eduid.scimapi.context_request import ScimApiContext
from eduid.scimapi.exceptions import BadRequest
from eduid.scimapi.models.event import EventResponse, NutidEventExtensionV1, NutidEventResource
from eduid.userdb.scimapi import EventLevel, EventStatus, ScimApiEvent, ScimApiEventResource, ScimApiResourceBase

if TYPE_CHECKING:
    from eduid.scimapi.context import Context

from eduid.common.misc.timeutil import utc_now

__author__ = "lundberg"


def db_event_to_response(req: ContextRequest, resp: Response, db_event: ScimApiEvent) -> EventResponse:
    location = req.app.context.resource_url(SCIMResourceType.EVENT, db_event.scim_id)
    meta = Meta(
        location=location,
        last_modified=db_event.last_modified,
        resource_type=SCIMResourceType.EVENT,
        created=db_event.created,
        version=db_event.version,
    )

    schemas = [SCIMSchema.NUTID_EVENT_CORE_V1, SCIMSchema.NUTID_EVENT_V1]
    event_response = EventResponse(
        id=db_event.scim_id,
        meta=meta,
        schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
        nutid_event_v1=NutidEventExtensionV1(
            level=db_event.level,
            data=db_event.data,
            source=db_event.source,
            expires_at=db_event.expires_at,
            timestamp=db_event.timestamp,
            resource=NutidEventResource(
                resource_type=db_event.resource.resource_type,
                version=db_event.resource.version,
                last_modified=db_event.resource.last_modified,
                scim_id=db_event.resource.scim_id,
                external_id=db_event.resource.external_id,
                location=req.app.context.resource_url(db_event.resource.resource_type, db_event.resource.scim_id),
            ),
        ),
    )

    resp.headers["Location"] = location
    resp.headers["ETag"] = make_etag(db_event.version)
    req.app.context.logger.debug(
        f"Extra debug: Response:\n{event_response.model_dump_json(exclude_none=True, indent=2)}"
    )
    return event_response


def get_scim_referenced(req: ContextRequest, resource: NutidEventResource) -> ScimApiResourceBase | None:
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.userdb is not None  # please mypy
    assert req.context.groupdb is not None  # please mypy
    assert req.context.invitedb is not None  # please mypy
    if resource.resource_type == SCIMResourceType.USER:
        return req.context.userdb.get_user_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.GROUP:
        return req.context.groupdb.get_group_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.INVITE:
        return req.context.invitedb.get_invite_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.EVENT:
        raise BadRequest(detail="Events can not refer to other events")
    raise BadRequest(detail=f"Events for resource {resource.resource_type.value} not implemented")


def add_api_event(
    data_owner: DataOwnerName,
    context: "Context",
    db_obj: ScimApiResourceBase,
    resource_type: SCIMResourceType,
    level: EventLevel,
    status: EventStatus,
    message: str,
) -> None:
    """Add an event with source=this-API."""
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
        source="eduID SCIM API",
        level=level,
        data={"v": 1, "status": status.value, "message": message},
    )
    event_db = context.get_eventdb(data_owner=data_owner)
    assert event_db  # please mypy
    event_db.save(_event)

    # Send notification
    event_location = urlappend(context.base_url, f"Events/{_event.scim_id}")
    message = context.notification_relay.format_message(version=1, data={"location": event_location})
    context.notification_relay.notify(data_owner=data_owner, message=message, context=context)
