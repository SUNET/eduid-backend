# -*- coding: utf-8 -*-
from typing import Any

from falcon import Request, Response

from eduid_scimapi.exceptions import BadRequest
from eduid_scimapi.resources.base import SCIMResource
from eduid_scimapi.schemas.invite import InviteCreateRequest, InviteCreateRequestSchema, InviteResponse
from eduid_scimapi.schemas.scimbase import Meta, SCIMResourceType, SCIMSchema
from eduid_scimapi.schemas.user import NutidExtensionV1

__author__ = 'lundberg'


class InvitesResource(SCIMResource):
    def _db_invite_to_response(self, req: Request, resp: Response, db_invite):
        location = self.url_for("Invites", db_invite.scim_id)
        meta = Meta(
            location=location,
            last_modified=db_invite.last_modified,
            resource_type=SCIMResourceType.user,
            created=db_invite.created,
            version=db_invite.version,
        )

        schemas = [SCIMSchema.CORE_20_USER, SCIMSchema.NUTID_INVITE_V1]

        user = InviteResponse(
            id=db_invite.scim_id,
            external_id=db_invite.external_id,
            name=db_invite.name,
            emails=db_invite.emails,
            meta=meta,
            schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
            nutid_v1=NutidInV1(profiles=_profiles),
        )

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_user.version))
        resp.media = UserResponseSchema().dump(user)

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

            # db_invite = ScimApiInvite()
            # ctx_invitedb(req).save(db_invite)

            # self._db_invite_to_response(req=req, resp=resp, db_invite=db_invite)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")
