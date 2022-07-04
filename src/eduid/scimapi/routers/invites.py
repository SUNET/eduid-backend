# -*- coding: utf-8 -*-
from typing import Optional

from fastapi import Response

from eduid.scimapi.api_router import APIRouter
from eduid.scimapi.context_request import ContextRequest, ContextRequestRoute
from eduid.scimapi.db.common import ScimApiEmail, ScimApiName, ScimApiPhoneNumber, ScimApiProfile
from eduid.scimapi.db.eventdb import EventLevel, EventStatus, add_api_event
from eduid.scimapi.db.invitedb import ScimApiInvite
from eduid.scimapi.exceptions import BadRequest, ErrorDetail, NotFound
from eduid.scimapi.models.invite import InviteCreateRequest, InviteResponse
from eduid.scimapi.models.scimbase import ListResponse, SCIMResourceType, SearchRequest
from eduid.scimapi.routers.utils.invites import (
    create_signup_invite,
    create_signup_ref,
    db_invite_to_response,
    filter_lastmodified,
    invites_to_resources_dicts,
    send_invite_mail,
)
from eduid.scimapi.search import parse_search_filter

__author__ = 'lundberg'

invites_router = APIRouter(
    route_class=ContextRequestRoute,
    prefix='/Invites',
    responses={
        400: {'description': 'Bad request', 'model': ErrorDetail},
        404: {'description': 'Not found', 'model': ErrorDetail},
        500: {'description': 'Internal server error', 'model': ErrorDetail},
    },
)


@invites_router.get('/{scim_id}', response_model=InviteResponse, response_model_exclude_none=True)
async def on_get(req: ContextRequest, resp: Response, scim_id: Optional[str] = None) -> InviteResponse:
    if scim_id is None:
        raise BadRequest(detail='Not implemented')
    req.app.context.logger.info(f'Fetching invite {scim_id}')
    db_invite = req.context.invitedb.get_invite_by_scim_id(scim_id)
    if not db_invite:
        raise NotFound(detail='Invite not found')
    ref = create_signup_ref(req, db_invite)
    signup_invite = req.app.context.signup_invitedb.get_invite_by_reference(ref)
    if signup_invite is None:
        raise NotFound(detail='Invite reference not found')
    return db_invite_to_response(req, resp, db_invite, signup_invite)


@invites_router.post('/', response_model=InviteResponse, response_model_exclude_none=True)
async def on_post(req: ContextRequest, resp: Response, create_request: InviteCreateRequest) -> InviteResponse:
    """
    POST /Invites  HTTP/1.1
    Host: example.com
    Accept: application/scim+json
    Content-Type: application/scim+json
    Authorization: Bearer h480djs93hd8
    Content-Length: ...

     {
         'schemas': ['https://scim.eduid.se/schema/nutid/invite/v1',
                     'https://scim.eduid.se/schema/nutid/user/v1'],
         'expiresAt': '2021-03-02T14:35:52',
         'groups': [],
         'phoneNumbers': [
             {'type': 'fax', 'value': 'tel:+461234567', 'primary': True},
             {'type': 'home', 'value': 'tel:+5-555-555-5555', 'primary': False},
         ],
         'meta': {
             'location': 'http://localhost:8000/Invites/fb96a6d0-1837-4c3b-9945-4249c476875c',
             'resourceType': 'Invite',
             'created': '2020-09-03T14:35:52.381881',
             'version': 'W/"5f50ff48df3ce45b48394eb2"',
             'lastModified': '2020-09-03T14:35:52.388959',
         },
         'nationalIdentityNumber': '190102031234',
         'id': 'fb96a6d0-1837-4c3b-9945-4249c476875c',
         'preferredLanguage': 'se-SV',
         'sendEmail': True,
         'name': {
             'familyName': 'Testsson',
             'middleName': 'Testaren',
             'formatted': 'Test T. Testsson',
             'givenName': 'Test',
         },
         'finishURL': 'https://finish.example.com',
         'https://scim.eduid.se/schema/nutid/user/v1': {
             'profiles': {'student': {'attributes': {'displayName': 'Test'}, 'data': {}}}
         },
         'emails': [
             {'type': 'other', 'value': 'johnsmith@example.com', 'primary': True},
             {'type': 'home', 'value': 'johnsmith2@example.com', 'primary': False},
         ],
     }
    """
    req.app.context.logger.info(f'Creating invite')
    profiles = {}
    for profile_name, profile in create_request.nutid_user_v1.profiles.items():
        profiles[profile_name] = ScimApiProfile(attributes=profile.attributes, data=profile.data)

    db_invite = ScimApiInvite(
        external_id=create_request.external_id,
        name=ScimApiName(**create_request.nutid_invite_v1.name.dict()),
        emails=[ScimApiEmail(**email.dict()) for email in create_request.nutid_invite_v1.emails],
        phone_numbers=[ScimApiPhoneNumber(**number.dict()) for number in create_request.nutid_invite_v1.phone_numbers],
        nin=create_request.nutid_invite_v1.national_identity_number,
        preferred_language=create_request.nutid_invite_v1.preferred_language,
        groups=create_request.nutid_invite_v1.groups,
        profiles=profiles,
    )
    signup_invite = create_signup_invite(req, create_request, db_invite)
    req.app.context.signup_invitedb.save(signup_invite)
    req.context.invitedb.save(db_invite)
    if signup_invite.send_email:
        send_invite_mail(req, signup_invite)

    add_api_event(
        context=req.app.context,
        data_owner=req.context.data_owner,
        db_obj=db_invite,
        resource_type=SCIMResourceType.INVITE,
        level=EventLevel.INFO,
        status=EventStatus.CREATED,
        message='Invite was created',
    )

    resp.status_code = 201
    return db_invite_to_response(req, resp, db_invite, signup_invite)


@invites_router.delete('/{scim_id}', status_code=204, responses={204: {'description': 'No Content'}})
async def on_delete(req: ContextRequest, scim_id: str) -> None:
    req.app.context.logger.info(f'Deleting invite {scim_id}')
    db_invite = req.context.invitedb.get_invite_by_scim_id(scim_id=scim_id)
    req.app.context.logger.debug(f'Found invite: {db_invite}')

    if not db_invite:
        raise NotFound(detail="Invite not found")

    # Check version
    if not req.app.context.check_version(req, db_invite):
        raise BadRequest(detail="Version mismatch")

    # Remove signup invite
    ref = create_signup_ref(req, db_invite)
    signup_invite = req.app.context.signup_invitedb.get_invite_by_reference(ref)
    if signup_invite:
        req.app.context.signup_invitedb.remove_document(signup_invite.invite_id)

    # Remove scim invite
    res = req.context.invitedb.remove(db_invite)

    add_api_event(
        context=req.app.context,
        data_owner=req.context.data_owner,
        db_obj=db_invite,
        resource_type=SCIMResourceType.INVITE,
        level=EventLevel.INFO,
        status=EventStatus.DELETED,
        message='Invite was deleted',
    )

    req.app.context.logger.debug(f'Remove invite result: {res}')


@invites_router.post('/.search', response_model=ListResponse, response_model_exclude_none=True)
async def search(req: ContextRequest, query: SearchRequest) -> ListResponse:
    """
    POST /Invites/.search
    Host: scim.eduid.se
    Accept: application/scim+json

    {
      "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
      "attributes": ["id"],
      "filter": "meta.lastModified ge \"2020-09-14T12:49:45\"",
      "encryptionKey": "h026jGKrSW%2BTTekkA8Y8mv8%2FGqkGgAfLzaj3ucD3STQ"
      "startIndex": 1,
      "count": 1
    }

    HTTP/1.1 200 OK
    Content-Type: application/scim+json
    Location: https://example.com/Invites/.search

    {
      "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      "totalResults": 1,
      "itemsPerPage": 1,
      "startIndex": 1,
      "Resources": [
        {
          "id": "fb96a6d0-1837-4c3b-9945-4249c476875c",
        }
      ]
    }
    """
    req.app.context.logger.info(f'Searching for users(s)')
    req.app.context.logger.debug(f'Parsed user search query: {query}')

    filter = parse_search_filter(query.filter)

    if filter.attr == 'meta.lastmodified':
        # SCIM start_index 1 equals item 0
        users, total_count = filter_lastmodified(req, filter, skip=query.start_index - 1, limit=query.count)
    else:
        raise BadRequest(scim_type='invalidFilter', detail=f'Can\'t filter on attribute {filter.attr}')

    return ListResponse(resources=invites_to_resources_dicts(query, users), total_results=total_count)
