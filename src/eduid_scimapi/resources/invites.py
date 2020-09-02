# -*- coding: utf-8 -*-
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from falcon import Request, Response
from marshmallow import ValidationError

from eduid_common.api.utils import get_short_hash, get_unique_hash
from eduid_userdb.mail import MailAddress, MailAddressList
from eduid_userdb.signup import Invite as SignupInvite
from eduid_userdb.signup import InviteType, SCIMReference

from eduid_scimapi.db.invitedb import ScimApiInvite
from eduid_scimapi.exceptions import BadRequest
from eduid_scimapi.middleware import ctx_invitedb
from eduid_scimapi.resources.base import SCIMResource
from eduid_scimapi.schemas.invite import (
    InviteCreateRequest,
    InviteCreateRequestSchema,
    InviteResponse,
    InviteResponseSchema,
    NutidExtensionV1,
)
from eduid_scimapi.schemas.scimbase import Meta, SCIMResourceType, SCIMSchema
from eduid_scimapi.utils import make_etag

__author__ = 'lundberg'


class InvitesResource(SCIMResource):
    def _create_signup_invite(
        self, req: Request, resp: Response, create_request: InviteCreateRequest, db_invite: ScimApiInvite
    ) -> SignupInvite:
        invite_reference = SCIMReference(data_owner=req.context['data_owner'], scim_id=db_invite.scim_id)

        if create_request.nutid_v1.send_email is False:
            # Generate a shorter code if the code will reach the invitee on paper or other analog media
            invite_code = get_short_hash()
            mail_address_list = None
        else:
            invite_code = get_unique_hash()
            addresses = []
            for email in create_request.emails:
                addresses.append(MailAddress(email=email.value, application='eduid-scimapi', primary=email.primary))
            mail_address_list = MailAddressList(addresses)

        signup_invite = SignupInvite(
            invite_code=invite_code,
            invite_type=InviteType.SCIM,
            invite_reference=invite_reference,
            display_name=create_request.name.formatted,
            given_name=create_request.name.givenName,
            surname=create_request.name.familyName,
            send_email=create_request.nutid_v1.send_email,
            mail_addresses=mail_address_list,
            finish_url=create_request.nutid_v1.finish_url,
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

        schemas = [SCIMSchema.CORE_20_USER, SCIMSchema.NUTID_INVITE_V1]
        invite = InviteResponse(
            id=db_invite.scim_id,
            external_id=db_invite.external_id,
            name=db_invite.name,
            emails=db_invite.emails,
            meta=meta,
            schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
            nutid_v1=NutidExtensionV1(
                send_email=signup_invite.send_email,
                finish_url=signup_invite.finish_url,
                completed=db_invite.completed,
                expires_at=signup_invite.expires_at,
            ),
        )

        # Only add invite url in response if no email should be sent to the invitee
        if signup_invite.send_email is False:
            invite_url = f'{self.context.config.invite_url}/{signup_invite.invite_code}'
            nutid_v1 = replace(invite.nutid_v1, invite_url=invite_url)
            invite = replace(invite, nutid_v1=nutid_v1)

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_invite.version))
        resp.media = InviteResponseSchema().dump(invite)

    def on_post(self, req: Request, resp: Response):
        """
               POST /Invites  HTTP/1.1
               Host: example.com
               Accept: application/scim+json
               Content-Type: application/scim+json
               Authorization: Bearer h480djs93hd8
               Content-Length: ...

               {
                 "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
                 "name":{
                   "formatted":"Ms. Barbara J Jensen III",
                   "familyName":"Jensen",
                   "givenName":"Barbara"
                 },
                 "emails":[
                   {
                       "value":"bjensen@example.com"
                   }
                 ],
               }


               HTTP/1.1 201 Created
               Content-Type: application/scim+json
               Location:
                https://example.com/v2/Invites/2819c223-7f76-453a-919d-413861904646
               ETag: W/"e180ee84f0671b1"

               {
                 "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
                 "id":"2819c223-7f76-453a-919d-413861904646",
                 "externalId":"bjensen",
                 "meta":{
                   "resourceType":"Invite",
                   "created":"2011-08-01T21:32:44.882Z",
                   "lastModified":"2011-08-01T21:32:44.882Z",
                   "location": "https://example.com/v2/Invites/2819c223-7f76-453a-919d-413861904646",
                   "version":"W\/\"e180ee84f0671b1\""
                 },
                 "name":{
                   "formatted":"Ms. Barbara J Jensen III",
                   "familyName":"Jensen",
                   "givenName":"Barbara"
                 },
                 "emails":[
                   {
                       "value":"bjensen@example.com"
                   }
                 ],
               }
        """
        try:
            self.context.logger.info(f'Creating invite')

            create_request: InviteCreateRequest = InviteCreateRequestSchema().load(req.media)
            self.context.logger.debug(create_request)

            db_invite = ScimApiInvite(name=create_request.name, emails=create_request.emails,)
            signup_invite = self._create_signup_invite(req, resp, create_request, db_invite)
            self.context.signup_invitedb.save(signup_invite)
            ctx_invitedb(req).save(db_invite)

            self._db_invite_to_response(req, resp, db_invite, signup_invite)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")
