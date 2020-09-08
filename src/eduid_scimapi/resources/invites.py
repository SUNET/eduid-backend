# -*- coding: utf-8 -*-
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from typing import Optional

from falcon import HTTP_204, Request, Response
from marshmallow import ValidationError

from eduid_userdb.signup import Invite as SignupInvite
from eduid_userdb.signup import InviteMailAddress, InvitePhoneNumber, InviteType, SCIMReference

from eduid_scimapi.db.common import ScimApiEmail, ScimApiName, ScimApiPhoneNumber, ScimApiProfile
from eduid_scimapi.db.invitedb import ScimApiInvite
from eduid_scimapi.exceptions import BadRequest, NotFound
from eduid_scimapi.middleware import ctx_invitedb
from eduid_scimapi.resources.base import SCIMResource
from eduid_scimapi.schemas.invite import (
    InviteCreateRequest,
    InviteCreateRequestSchema,
    InviteResponse,
    InviteResponseSchema,
)
from eduid_scimapi.schemas.scimbase import Email, Meta, Name, PhoneNumber, SCIMResourceType, SCIMSchema
from eduid_scimapi.schemas.user import NutidUserExtensionV1, Profile
from eduid_scimapi.utils import get_short_hash, get_unique_hash, make_etag

__author__ = 'lundberg'


class InvitesResource(SCIMResource):
    def _create_signup_invite(
        self, req: Request, resp: Response, create_request: InviteCreateRequest, db_invite: ScimApiInvite
    ) -> SignupInvite:
        invite_reference = SCIMReference(data_owner=req.context['data_owner'], scim_id=db_invite.scim_id)

        if create_request.send_email is False:
            # Generate a shorter code if the code will reach the invitee on paper or other analog media
            invite_code = get_short_hash()
        else:
            invite_code = get_unique_hash()

        mails_addresses = [
            InviteMailAddress(email=email.value, primary=email.primary) for email in create_request.emails
        ]
        phone_numbers = [
            InvitePhoneNumber(number=number.value, primary=number.primary) for number in create_request.phone_numbers
        ]

        signup_invite = SignupInvite(
            invite_code=invite_code,
            invite_type=InviteType.SCIM,
            invite_reference=invite_reference,
            display_name=create_request.name.formatted,
            given_name=create_request.name.givenName,
            surname=create_request.name.familyName,
            nin=create_request.national_identity_number,
            inviter_name=create_request.inviter_name,
            send_email=create_request.send_email,
            mail_addresses=mails_addresses,
            phone_numbers=phone_numbers,
            finish_url=create_request.finish_url,
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

        schemas = [SCIMSchema.NUTID_INVITE_V1, SCIMSchema.NUTID_USER_V1]
        _profiles = {k: Profile(attributes=v.attributes, data=v.data) for k, v in db_invite.profiles.items()}
        invite = InviteResponse(
            id=db_invite.scim_id,
            external_id=db_invite.external_id,
            completed=db_invite.completed,
            name=Name(**asdict(db_invite.name)),
            emails=[Email(**asdict(email)) for email in db_invite.emails],
            phone_numbers=[PhoneNumber(**asdict(number)) for number in db_invite.phone_numbers],
            national_identity_number=db_invite.nin,
            preferred_language=db_invite.preferred_language,
            groups=db_invite.groups,
            meta=meta,
            schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
            send_email=signup_invite.send_email,
            finish_url=signup_invite.finish_url,
            expires_at=signup_invite.expires_at,
            inviter_name=signup_invite.inviter_name,
            nutid_user_v1=NutidUserExtensionV1(profiles=_profiles),
        )

        # Only add invite url in response if no email should be sent to the invitee
        if signup_invite.send_email is False:
            invite_url = f'{self.context.config.invite_url}/{signup_invite.invite_code}'
            invite = replace(invite, invite_url=invite_url)

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_invite.version))
        resp.media = InviteResponseSchema().dump(invite)

    @staticmethod
    def _create_signup_ref(req: Request, db_invite: ScimApiInvite):
        return SCIMReference(data_owner=req.context['data_owner'], scim_id=db_invite.scim_id)

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
                    'expires_at': '2021-03-02T14:35:52',
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
                    'preferred_language': 'se-SV',
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
            name=ScimApiName(**asdict(create_request.name)),
            emails=[ScimApiEmail(**asdict(email)) for email in create_request.emails],
            phone_numbers=[ScimApiPhoneNumber(**asdict(number)) for number in create_request.phone_numbers],
            nin=create_request.national_identity_number,
            preferred_language=create_request.preferred_language,
            groups=create_request.groups,
            profiles=profiles,
        )
        signup_invite = self._create_signup_invite(req, resp, create_request, db_invite)
        self.context.signup_invitedb.save(signup_invite)
        ctx_invitedb(req).save(db_invite)
        self._db_invite_to_response(req, resp, db_invite, signup_invite)

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
        self.context.logger.debug(f'Remove invite result: {res}')

        resp.status = HTTP_204
