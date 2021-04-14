# -*- coding: utf-8 -*-
import pprint
from datetime import timedelta
from typing import Optional

from falcon import Request, Response
from marshmallow import ValidationError

from eduid.scimapi.db.common import ScimApiResourceBase
from eduid.scimapi.db.eventdb import ScimApiEvent, ScimApiEventResource
from eduid.scimapi.exceptions import BadRequest, NotFound
from eduid.scimapi.middleware import ctx_eventdb, ctx_groupdb, ctx_invitedb, ctx_userdb
from eduid.scimapi.resources.base import SCIMResource
from eduid.scimapi.schemas.event import (
    EventCreateRequest,
    EventCreateRequestSchema,
    EventResponse,
    EventResponseSchema,
    NutidEventExtensionV1,
    NutidEventResource,
)
from eduid.scimapi.schemas.scimbase import Meta, SCIMResourceType, SCIMSchema
from eduid.scimapi.utils import make_etag

__author__ = 'lundberg'

from eduid.userdb.util import utc_now


class EventsResource(SCIMResource):
    def _db_event_to_response(self, req: Request, resp: Response, db_event: ScimApiEvent):
        location = self.resource_url(SCIMResourceType.EVENT, db_event.scim_id)
        meta = Meta(
            location=location,
            last_modified=db_event.last_modified,
            resource_type=SCIMResourceType.EVENT,
            created=db_event.created,
            version=db_event.version,
        )

        schemas = [SCIMSchema.NUTID_EVENT_CORE_V1, SCIMSchema.NUTID_EVENT_V1]
        response = EventResponse(
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
                    location=self.resource_url(db_event.resource.resource_type, db_event.resource.scim_id),
                ),
            ),
        )

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_event.version))
        resp.media = EventResponseSchema().dump(response)
        self.context.logger.debug(f'Extra debug: Response:\n{pprint.pformat(resp.media)}')

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
        self.context.logger.info(f'Creating event')
        try:
            create_request: EventCreateRequest = EventCreateRequestSchema().load(req.media)
            self.context.logger.debug(create_request)
        except ValidationError as e:
            raise BadRequest(detail=str(e))

        # TODO: Instead of checking input here we should use dump_only for the fields in the schema
        if create_request.nutid_event_v1.source:
            raise BadRequest(detail='source is read-only')
        if create_request.nutid_event_v1.expires_at:
            raise BadRequest(detail='expiresAt is read-only')
        if create_request.nutid_event_v1.resource.external_id:
            raise BadRequest(detail='resource.externalId is read-only')
        if create_request.nutid_event_v1.resource.location:
            raise BadRequest(detail='resource.location is read-only')

        # TODO: This check should move to schema validation
        if create_request.nutid_event_v1.timestamp:
            earliest_allowed = utc_now() - timedelta(days=1)
            if create_request.nutid_event_v1.timestamp < earliest_allowed:
                raise BadRequest(detail='timestamp is too old')

        referenced = _get_scim_referenced(req, create_request.nutid_event_v1.resource)
        if not referenced:
            raise BadRequest(detail='referenced object not found')

        _timestamp = utc_now()
        if create_request.nutid_event_v1.timestamp:
            _timestamp = create_request.nutid_event_v1.timestamp
        _expires_at = utc_now() + timedelta(days=1)

        event = ScimApiEvent(
            resource=ScimApiEventResource(
                resource_type=create_request.nutid_event_v1.resource.resource_type,
                version=create_request.nutid_event_v1.resource.version,
                last_modified=create_request.nutid_event_v1.resource.last_modified,
                scim_id=referenced.scim_id,
                external_id=referenced.external_id,
            ),
            level=create_request.nutid_event_v1.level,
            source=req.context['data_owner'],
            data=create_request.nutid_event_v1.data,
            expires_at=_expires_at,
            timestamp=_timestamp,
        )
        ctx_eventdb(req).save(event)

        # Send notification
        message = self.context.notification_relay.format_message(
            version=1, data={'location': self.resource_url(SCIMResourceType.EVENT, event.scim_id)}
        )
        self.context.notification_relay.notify(data_owner=req.context['data_owner'], message=message)

        self._db_event_to_response(req, resp, event)


def _get_scim_referenced(req: Request, resource: NutidEventResource) -> Optional[ScimApiResourceBase]:
    if resource.resource_type == SCIMResourceType.USER:
        return ctx_userdb(req).get_user_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.GROUP:
        return ctx_groupdb(req).get_group_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.INVITE:
        return ctx_invitedb(req).get_invite_by_scim_id(str(resource.scim_id))
    elif resource.resource_type == SCIMResourceType.EVENT:
        raise BadRequest(detail=f'Events can not refer to other events')
    raise BadRequest(detail=f'Events for resource {resource.resource_type.value} not implemented')
