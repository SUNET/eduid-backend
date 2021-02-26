# -*- coding: utf-8 -*-
from dataclasses import asdict, replace
from datetime import datetime, timedelta
from os import environ
from typing import Any, Dict, List, Optional, Sequence, Tuple

from eduid_queue.db import QueueItem, SenderInfo
from eduid_queue.db.message import EduidInviteEmail
from falcon import HTTP_201, HTTP_204, Request, Response
from marshmallow import ValidationError

from eduid_userdb.signup import Invite as SignupInvite
from eduid_userdb.signup import InviteMailAddress, InvitePhoneNumber, InviteType, SCIMReference

from eduid_scimapi.db.common import ScimApiEmail, ScimApiName, ScimApiPhoneNumber, ScimApiProfile
from eduid_scimapi.db.eventdb import EventLevel, EventStatus, add_api_event
from eduid_scimapi.db.invitedb import ScimApiInvite
from eduid_scimapi.exceptions import BadRequest, NotFound
from eduid_scimapi.middleware import ctx_invitedb
from eduid_scimapi.resources.base import BaseResource, SCIMResource
from eduid_scimapi.schemas.invite import (
    InviteCreateRequest,
    InviteCreateRequestSchema,
    InviteResponse,
    InviteResponseSchema,
    NutidInviteExtensionV1,
)
from eduid_scimapi.schemas.scimbase import (
    Email,
    ListResponse,
    ListResponseSchema,
    Meta,
    Name,
    PhoneNumber,
    SCIMResourceType,
    SCIMSchema,
    SearchRequest,
    SearchRequestSchema,
)
from eduid_scimapi.schemas.user import NutidUserExtensionV1, Profile
from eduid_scimapi.search import SearchFilter, parse_search_filter
from eduid_scimapi.utils import get_short_hash, get_unique_hash, make_etag

__author__ = 'lundberg'


class InvitesResource(SCIMResource):
    def _create_signup_invite(
        self, req: Request, resp: Response, create_request: InviteCreateRequest, db_invite: ScimApiInvite
    ) -> SignupInvite:
        invite_reference = SCIMReference(data_owner=req.context['data_owner'], scim_id=db_invite.scim_id)

        if create_request.nutid_invite_v1.send_email is False:
            # Generate a shorter code if the code will reach the invitee on paper or other analog media
            invite_code = get_short_hash()
        else:
            invite_code = get_unique_hash()

        mails_addresses = [
            InviteMailAddress(email=email.value, primary=email.primary)
            for email in create_request.nutid_invite_v1.emails
        ]
        phone_numbers = [
            InvitePhoneNumber(number=number.value, primary=number.primary)
            for number in create_request.nutid_invite_v1.phone_numbers
        ]

        signup_invite = SignupInvite(
            invite_code=invite_code,
            invite_type=InviteType.SCIM,
            invite_reference=invite_reference,
            display_name=create_request.nutid_invite_v1.name.formatted,
            given_name=create_request.nutid_invite_v1.name.given_name,
            surname=create_request.nutid_invite_v1.name.family_name,
            nin=create_request.nutid_invite_v1.national_identity_number,
            inviter_name=create_request.nutid_invite_v1.inviter_name,
            send_email=create_request.nutid_invite_v1.send_email,
            mail_addresses=mails_addresses,
            phone_numbers=phone_numbers,
            finish_url=create_request.nutid_invite_v1.finish_url,
            expires_at=datetime.utcnow() + timedelta(seconds=self.context.config.invite_expire),
        )
        return signup_invite

    def _db_invite_to_response(
        self, req: Request, resp: Response, db_invite: ScimApiInvite, signup_invite: SignupInvite
    ):
        location = self.url_for("Invites", db_invite.scim_id)
        meta = Meta(
            location=location,
            last_modified=db_invite.last_modified,
            resource_type=SCIMResourceType.INVITE,
            created=db_invite.created,
            version=db_invite.version,
        )

        schemas = [SCIMSchema.NUTID_INVITE_CORE_V1, SCIMSchema.NUTID_INVITE_V1, SCIMSchema.NUTID_USER_V1]
        _profiles = {k: Profile(attributes=v.attributes, data=v.data) for k, v in db_invite.profiles.items()}
        invite_extension = NutidInviteExtensionV1(
            completed=db_invite.completed,
            name=Name(**asdict(db_invite.name)),
            emails=[Email(**asdict(email)) for email in db_invite.emails],
            phone_numbers=[PhoneNumber(**asdict(number)) for number in db_invite.phone_numbers],
            national_identity_number=db_invite.nin,
            preferred_language=db_invite.preferred_language,
            groups=db_invite.groups,
            send_email=signup_invite.send_email,
            finish_url=signup_invite.finish_url,
            expires_at=signup_invite.expires_at,
            inviter_name=signup_invite.inviter_name,
        )
        # Only add invite url in response if no email should be sent to the invitee
        if signup_invite.send_email is False:
            invite_url = f'{self.context.config.invite_url}/{signup_invite.invite_code}'
            invite_extension = replace(invite_extension, invite_url=invite_url)

        scim_invite = InviteResponse(
            id=db_invite.scim_id,
            external_id=db_invite.external_id,
            meta=meta,
            schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
            nutid_invite_v1=invite_extension,
            nutid_user_v1=NutidUserExtensionV1(profiles=_profiles),
        )

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_invite.version))
        resp.media = InviteResponseSchema().dump(scim_invite)

    @staticmethod
    def _create_signup_ref(req: Request, db_invite: ScimApiInvite):
        return SCIMReference(data_owner=req.context['data_owner'], scim_id=db_invite.scim_id)

    def _send_invite_mail(self, signup_invite: SignupInvite):
        try:
            email = [email.email for email in signup_invite.mail_addresses if email.primary][0]
        except IndexError:
            # Primary not set
            email = signup_invite.mail_addresses[0].email
        link = f'{self.context.config.invite_url}/{signup_invite.invite_code}'
        payload = EduidInviteEmail(
            email=email,
            reference=str(signup_invite.invite_id),
            invite_link=link,
            invite_code=signup_invite.invite_code,
            inviter_name=signup_invite.inviter_name,
            language=signup_invite.preferred_language,
        )
        app_name = self.context.name
        system_hostname = environ.get('SYSTEM_HOSTNAME', '')  # Underlying hosts name for containers
        hostname = environ.get('HOSTNAME', '')  # Actual hostname or container id
        sender_info = SenderInfo(hostname=hostname, node_id=f'{app_name}@{system_hostname}')
        expires_at = datetime.utcnow() + timedelta(seconds=self.context.config.invite_expire)
        discard_at = expires_at + timedelta(days=7)
        message = QueueItem(
            version=1,
            expires_at=expires_at,
            discard_at=discard_at,
            sender_info=sender_info,
            payload_type=payload.get_type(),
            payload=payload,
        )
        self.context.messagedb.save(message)
        self.context.logger.info(f'Saved invite email to address {email} in message queue')
        return True

    def on_get(self, req: Request, resp: Response, scim_id: Optional[str] = None):
        if scim_id is None:
            raise BadRequest(detail='Not implemented')
        self.context.logger.info(f'Fetching invite {scim_id}')
        db_invite = ctx_invitedb(req).get_invite_by_scim_id(scim_id)
        if not db_invite:
            raise NotFound(detail='Invite not found')
        ref = self._create_signup_ref(req, db_invite)
        signup_invite = self.context.signup_invitedb.get_invite_by_reference(ref)
        self._db_invite_to_response(req, resp, db_invite, signup_invite)

    def on_post(self, req: Request, resp: Response):
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
        self.context.logger.info(f'Creating invite')
        try:
            create_request: InviteCreateRequest = InviteCreateRequestSchema().load(req.media)
            self.context.logger.debug(create_request)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")

        profiles = {}
        for profile_name, profile in create_request.nutid_user_v1.profiles.items():
            profiles[profile_name] = ScimApiProfile(attributes=profile.attributes, data=profile.data)

        db_invite = ScimApiInvite(
            external_id=create_request.external_id,
            name=ScimApiName(**asdict(create_request.nutid_invite_v1.name)),
            emails=[ScimApiEmail(**asdict(email)) for email in create_request.nutid_invite_v1.emails],
            phone_numbers=[
                ScimApiPhoneNumber(**asdict(number)) for number in create_request.nutid_invite_v1.phone_numbers
            ],
            nin=create_request.nutid_invite_v1.national_identity_number,
            preferred_language=create_request.nutid_invite_v1.preferred_language,
            groups=create_request.nutid_invite_v1.groups,
            profiles=profiles,
        )
        signup_invite = self._create_signup_invite(req, resp, create_request, db_invite)
        self.context.signup_invitedb.save(signup_invite)
        ctx_invitedb(req).save(db_invite)
        if signup_invite.send_email:
            self._send_invite_mail(signup_invite)

        add_api_event(
            context=self.context,
            data_owner=req.context['data_owner'],
            db_obj=db_invite,
            resource_type=SCIMResourceType.INVITE,
            level=EventLevel.INFO,
            status=EventStatus.CREATED,
            message='Invite was created',
        )

        self._db_invite_to_response(req, resp, db_invite, signup_invite)
        resp.status = HTTP_201

    def on_delete(self, req: Request, resp: Response, scim_id: str):
        self.context.logger.info(f'Deleting invite {scim_id}')
        db_invite = ctx_invitedb(req).get_invite_by_scim_id(scim_id=scim_id)
        self.context.logger.debug(f'Found invite: {db_invite}')

        if not db_invite:
            raise NotFound(detail="Invite not found")
        # Check version
        if not self._check_version(req, db_invite):
            raise BadRequest(detail="Version mismatch")

        # Remove signup invite
        ref = self._create_signup_ref(req, db_invite)
        signup_invite = self.context.signup_invitedb.get_invite_by_reference(ref)
        self.context.signup_invitedb.remove_document(signup_invite.invite_id)

        # Remove scim invite
        res = ctx_invitedb(req).remove(db_invite)

        add_api_event(
            context=self.context,
            data_owner=req.context['data_owner'],
            db_obj=db_invite,
            resource_type=SCIMResourceType.INVITE,
            level=EventLevel.INFO,
            status=EventStatus.DELETED,
            message='Group was deleted',
        )

        self.context.logger.debug(f'Remove invite result: {res}')
        resp.status = HTTP_204


class InviteSearchResource(BaseResource):
    def on_post(self, req: Request, resp: Response):
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
        self.context.logger.info(f'Searching for users(s)')

        try:
            query: SearchRequest = SearchRequestSchema().load(req.media)
        except ValidationError as e:
            raise BadRequest(detail=f'{e}')

        self.context.logger.debug(f'Parsed user search query: {query}')

        filter = parse_search_filter(query.filter)

        if filter.attr == 'meta.lastmodified':
            # SCIM start_index 1 equals item 0
            users, total_count = self._filter_lastmodified(req, filter, skip=query.start_index - 1, limit=query.count)
        else:
            raise BadRequest(scim_type='invalidFilter', detail=f'Can\'t filter on attribute {filter.attr}')

        list_response = ListResponse(resources=self._invites_to_resources_dicts(req, users), total_results=total_count)

        resp.media = ListResponseSchema().dump(list_response)

    @staticmethod
    def _invites_to_resources_dicts(req: Request, invites: Sequence[ScimApiInvite]) -> List[Dict[str, Any]]:
        _attributes = req.media.get('attributes')
        # TODO: include the requested attributes, not just id
        return [{'id': str(invite.scim_id)} for invite in invites]

    @staticmethod
    def _filter_lastmodified(
        req: Request, filter: SearchFilter, skip: Optional[int] = None, limit: Optional[int] = None
    ) -> Tuple[List[ScimApiInvite], int]:
        if filter.op not in ['gt', 'ge']:
            raise BadRequest(scim_type='invalidFilter', detail='Unsupported operator')
        if not isinstance(filter.val, str):
            raise BadRequest(scim_type='invalidFilter', detail='Invalid datetime')
        return ctx_invitedb(req).get_invites_by_last_modified(
            operator=filter.op, value=datetime.fromisoformat(filter.val), skip=skip, limit=limit
        )
