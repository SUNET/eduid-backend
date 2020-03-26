import re
from typing import Optional
from uuid import UUID

from falcon import Request, Response
from marshmallow.exceptions import ValidationError

from eduid_groupdb import Group as DBGroup
from eduid_groupdb import User as DBUser
from eduid_groupdb.exceptions import MultipleReturnedError
from eduid_scimapi.exceptions import BadRequest, ServerInternal
from eduid_scimapi.group import (
    Group,
    GroupCreateRequestSchema,
    GroupMember,
    GroupResponse,
    GroupResponseSchema,
    GroupUpdateRequest,
    GroupUpdateRequestSchema,
)
from eduid_scimapi.profile import Profile
from eduid_scimapi.resources.base import BaseResource
from eduid_scimapi.scimbase import BaseCreateRequest, BaseResponse, Meta, SCIMResourceType, SCIMSchema


class GroupsResource(BaseResource):
    def _db_group_to_response(self, resp: Response, db_group: DBGroup):
        members = []
        for member in db_group.member_users:
            ref = self.url_for("Users", member.identifier)
            members.append(GroupMember(value=UUID(member.identifier), ref=ref, display=member.display_name))
        for member in db_group.member_groups:
            ref = self.url_for("Groups", member.identifier)
            members.append(GroupMember(value=UUID(member.identifier), ref=ref, display=member.display_name))

        location = self.url_for("Groups", db_group.identifier)
        meta = Meta(
            location=location,
            last_modified=db_group.modified_ts,
            resource_type=SCIMResourceType.group,
            created=db_group.created_ts,
            version=db_group.version,
        )
        group = GroupResponse(
            display_name=db_group.display_name,
            members=members,
            id=UUID(db_group.identifier),
            meta=meta,
            schemas=[SCIMSchema.CORE_20_GROUP],
        )

        resp.set_header("Location", location)
        resp.set_header("ETag", f'W/"{db_group.version}"')
        resp.media = GroupResponseSchema().dump(group)

    def on_get(self, req: Request, resp: Response, scim_id):
        """
        GET /Groups/c3819cbe-c893-4070-824c-fe3d0db8f955  HTTP/1.1
        Host: example.com
        Accept: application/scim+json
        Content-Type: application/scim+json
        Authorization: Bearer h480djs93hd8
        Content-Length: ...

        HTTP/1.1 200 OK
        content-type: application/json; charset=UTF-8
        etag: W/"5e79df24f77769b475177bc7"
        location: http://scimapi.eduid.docker/scim/test/Groups/c3819cbe-c893-4070-824c-fe3d0db8f955

        {
            "displayName": "test group",
            "id": "c3819cbe-c893-4070-824c-fe3d0db8f955",
            "members": [],
            "meta": {
                "created": "2020-03-24T10:21:24.686000",
                "lastModified": null,
                "location": "http://scimapi.eduid.docker/scim/test/Groups/c3819cbe-c893-4070-824c-fe3d0db8f955",
                "resourceType": "Group",
                "version": "5e79df24f77769b475177bc7"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:Group"
            ]
        }
        """
        self.context.logger.info(f"Fetching group {scim_id}")
        scope = 'eduid.se'

        db_group: DBGroup = self.context.groupdb.get_group_by_scim_id(scope=scope, identifier=scim_id)
        self.context.logger.debug(f'Found group: {db_group}')
        if not db_group:
            raise BadRequest(detail="Group not found")
        self._db_group_to_response(resp, db_group)

    def on_put(self, req: Request, resp: Response, scim_id):
        try:
            group: GroupUpdateRequest = GroupUpdateRequestSchema().load(req.media)
            self.context.logger.debug(group)

            self.context.logger.info(f"Fetching group {scim_id}")
            # TODO: Figure out scope
            scope = 'eduid.se'

            # Get group from db
            db_group: DBGroup = self.context.groupdb.get_group_by_scim_id(scope=scope, identifier=group.id)
            self.context.logger.debug(f'Found group: {db_group}')
            if not db_group:
                raise BadRequest(detail='Group not found')

            # Check version
            if req.headers.get('If-Match') != f'W/"{db_group.version}"':
                raise BadRequest(detail="Version mismatch")

            # Check that members exists in their respective db
            for member in group.members:
                if 'Groups' in member.ref:
                    if not self.context.groupdb.group_exists(scope=scope, identifier=member.value):
                        raise BadRequest(detail=f'Group {member.value} not found')
                if 'Users' in member.ref:
                    if not self.context.userdb.user_exists(scim_id=member.value):
                        raise BadRequest(detail=f'User {member.value} not found')

            db_group = self.context.groupdb.update_group(scim_group=group, db_group=db_group)
            self._db_group_to_response(resp, db_group)
        except (ValidationError, MultipleReturnedError) as e:
            raise BadRequest(detail=f"{e}")

    def on_post(self, req: Request, resp: Response):
        """
        POST /Groups  HTTP/1.1
        Host: example.com
        Accept: application/scim+json
        Content-Type: application/scim+json
        Authorization: Bearer h480djs93hd8
        Content-Length: ...

        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Test SCIMv2",
            "members": []
        }


        HTTP/1.1 201 Created
        Date: Tue, 10 Sep 2019 04:54:18 GMT
        Content-Type: text/json;charset=UTF-8

        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "id": "abf4dd94-a4c0-4f67-89c9-76b03340cb9b",
            "displayName": "Test SCIMv2",
            "members": [],
            "meta": {
                "resourceType": "Group"
            }
        }
        """
        # TODO: Figure out scope
        scope = 'eduid.se'

        self.context.logger.info(f"Creating group")
        try:
            group: Group = GroupCreateRequestSchema().load(req.media)
            self.context.logger.debug(group)
            db_group = self.context.groupdb.create_group(scope=scope, scim_group=group)
            resp.status = '201'
            self._db_group_to_response(resp, db_group)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")
