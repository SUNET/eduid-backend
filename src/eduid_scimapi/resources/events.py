# -*- coding: utf-8 -*-
from typing import Optional

from falcon import Request, Response
from marshmallow import ValidationError

from eduid_scimapi.db.common import ScimApiEvent
from eduid_scimapi.exceptions import BadRequest, NotFound
from eduid_scimapi.middleware import ctx_eventdb
from eduid_scimapi.resources.base import SCIMResource
from eduid_scimapi.schemas.event import EventCreateRequest, EventCreateRequestSchema, EventResponse, EventResponseSchema
from eduid_scimapi.schemas.scimbase import (
    Meta,
    SCIMResourceType,
    SCIMSchema,
)
from eduid_scimapi.utils import make_etag

__author__ = 'lundberg'


class EventsResource(SCIMResource):

    def _db_event_to_response(
        self, req: Request, resp: Response, db_event: ScimApiEvent
    ):
        location = self.url_for("Events", db_event.scim_id)
        meta = Meta(
            location=location,
            last_modified=db_event.last_modified,
            resource_type=SCIMResourceType.INVITE,
            created=db_event.created,
            version=db_event.version,
        )

        schemas = [SCIMSchema.NUTID_INVITE_V1]
        event = EventResponse(
            id=db_event.scim_id,
            meta=meta,
            schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
        )

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_event.version))
        resp.media = EventResponseSchema().dump(event)

    def on_get(self, req: Request, resp: Response, scim_id: Optional[str] = None):
        if scim_id is None:
            raise BadRequest(detail='Not implemented')
        self.context.logger.info(f'Fetching event {scim_id}')
        db_event = ctx_eventdb(req).get_event_by_scim_id(scim_id)
        if not db_event:
            raise NotFound(detail='Event not found')
        self._db_event_to_response(req, resp, db_event)

    def on_post(self, req: Request, resp: Response):
        """
               POST /Events  HTTP/1.1
               Host: example.com
               Accept: application/scim+json
               Content-Type: application/scim+json
               Authorization: Bearer h480djs93hd8
               Content-Length: ...

                {
                    'schemas': ['https://scim.eduid.se/schema/nutid/event/v1'],
                    'https://scim.eduid.se/schema/nutid/event/v1': {
                        ...
                    }
                }
        """
        self.context.logger.info(f'Creating event')
        try:
            create_request: EventCreateRequest = EventCreateRequestSchema().load(req.media)
            self.context.logger.debug(create_request)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")
        self._db_event_to_response(req, resp, db_event)
