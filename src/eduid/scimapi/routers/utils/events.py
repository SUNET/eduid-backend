# -*- coding: utf-8 -*-
from typing import Optional

from fastapi import Response

from eduid.scimapi.context_request import ContextRequest
from eduid.scimapi.db.common import ScimApiResourceBase
from eduid.scimapi.db.eventdb import ScimApiEvent
from eduid.scimapi.exceptions import BadRequest
from eduid.scimapi.models.event import EventResponse, NutidEventExtensionV1, NutidEventResource
from eduid.scimapi.models.scimbase import Meta, SCIMResourceType, SCIMSchema, WeakVersion
from eduid.scimapi.utils import make_etag

__author__ = 'lundberg'


def db_event_to_response(req: ContextRequest, resp: Response, db_event: ScimApiEvent):
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
                version=WeakVersion(db_event.resource.version),
                last_modified=db_event.resource.last_modified,
                scim_id=db_event.resource.scim_id,
                external_id=db_event.resource.external_id,
                location=req.app.context.resource_url(db_event.resource.resource_type, db_event.resource.scim_id),
            ),
        ),
    )

    resp.headers['Location'] = location
    resp.headers['ETag'] = make_etag(db_event.version)
    req.app.context.logger.debug(f'Extra debug: Response:\n{event_response.json(exclude_none=True, indent=2)}')
    return event_response


def get_scim_referenced(req: ContextRequest, resource: NutidEventResource) -> Optional[ScimApiResourceBase]:
    if resource.resource_type == SCIMResourceType.USER:
        return req.context.userdb.get_user_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.GROUP:
        return req.context.groupdb.get_group_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.INVITE:
        return req.context.invitedb.get_invite_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.EVENT:
        raise BadRequest(detail=f'Events can not refer to other events')
    raise BadRequest(detail=f'Events for resource {resource.resource_type.value} not implemented')
