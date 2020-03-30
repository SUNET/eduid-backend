import re
from typing import List, Optional
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
from eduid_scimapi.scimbase import (
    ListResponse,
    ListResponseSchema,
    Meta,
    SCIMResourceType,
    SCIMSchema,
    SearchRequest,
    SearchRequestSchema,
)


class GroupsResource(BaseResource):
    def _get_group_members(self, db_group: DBGroup) -> List[GroupMember]:
        members = []
        for member in db_group.member_users:
            ref = self.url_for("Users", member.identifier)
            members.append(GroupMember(value=UUID(member.identifier), ref=ref, display=member.display_name))
        for member in db_group.member_groups:
            ref = self.url_for("Groups", member.identifier)
            members.append(GroupMember(value=UUID(member.identifier), ref=ref, display=member.display_name))
        return members

    def _db_group_to_response(self, resp: Response, db_group: DBGroup):
        members = self._get_group_members(db_group)
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

    def on_get(self, req: Request, resp: Response, scim_id=None):
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
        # TODO: Figure out scope
        scope = 'eduid.se'

        if scim_id:
            self.context.logger.info(f"Fetching group {scim_id}")

            db_group: DBGroup = self.context.groupdb.get_group_by_scim_id(scope=scope, identifier=scim_id)
            self.context.logger.debug(f'Found group: {db_group}')
            if not db_group:
                raise BadRequest(detail="Group not found")
            self._db_group_to_response(resp, db_group)
        else:
            # Return all Groups for scope
            db_groups: List[DBGroup] = self.context.groupdb.get_groups_for_scope(scope=scope)
            list_response = ListResponse(total_results=len(db_groups))
            resources = []
            for db_group in db_groups:
                resources.append(
                    {'id': db_group.identifier, 'displayName': db_group.display_name,}
                )
            list_response.resources = resources
            resp.media = ListResponseSchema().dump(list_response)

    def on_put(self, req: Request, resp: Response, scim_id):
        """
        PUT /Groups/c3819cbe-c893-4070-824c-fe3d0db8f955  HTTP/1.1
        Host: example.com
        Accept: application/scim+json
        Content-Type: application/scim+json
        Authorization: Bearer h480djs93hd8
        If-Match: W/"5e79df24f77769b475177bc7"
        Content-Length: ...

        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Test SCIMv2",
            "members": [
               {
                 "value": "2819c223-7f76-453a-919d-413861904646",
                 "$ref": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
                 "display": "Babs Jensen"
               },
            ]
        }

        HTTP/1.1 200 OK
        content-type: application/json; charset=UTF-8
        etag: W/"5e79df24f77769b475177bc7"
        location: http://scimapi.eduid.docker/scim/test/Groups/c3819cbe-c893-4070-824c-fe3d0db8f955

        {
            "displayName": "test group",
            "id": "c3819cbe-c893-4070-824c-fe3d0db8f955",
            "members": [
               {
                 "value": "2819c223-7f76-453a-919d-413861904646",
                 "$ref": "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
                 "display": "Babs Jensen"
               },
            ],
            "meta": {
                "created": "2020-03-24T10:21:24.686000",
                "lastModified": 2020-03-25T14:42:24.686000,
                "location": "http://scimapi.eduid.docker/scim/test/Groups/c3819cbe-c893-4070-824c-fe3d0db8f955",
                "resourceType": "Group",
                "version": "3e79d424f77269f475177bc5"
            },
            "schemas": [
                "urn:ietf:params:scim:schemas:core:2.0:Group"
            ]
        }

        """
        try:
            group: GroupUpdateRequest = GroupUpdateRequestSchema().load(req.media)
            self.context.logger.debug(group)

            self.context.logger.info(f"Fetching group {scim_id}")
            # TODO: Figure out scope
            scope = 'eduid.se'

            # Get group from db
            db_group: DBGroup = self.context.groupdb.get_group_by_scim_id(scope=scope, identifier=str(group.id))
            self.context.logger.debug(f'Found group: {db_group}')
            if not db_group:
                raise BadRequest(detail='Group not found')

            # Check version
            if req.headers.get('IF-MATCH') != f'W/{db_group.version}':
                self.context.logger.error(f'Version mismatch')
                self.context.logger.debug(f'{req.headers.get("IF-MATCH")} != W/{db_group.version}')
                raise BadRequest(detail="Version mismatch")

            # Check that members exists in their respective db
            self.context.logger.info(f'Checking if group and user members exists')
            for member in group.members:
                if 'Groups' in member.ref:
                    if not self.context.groupdb.group_exists(scope=scope, identifier=str(member.value)):
                        self.context.logger.error(f'Group {member.value} not found')
                        raise BadRequest(detail=f'Group {member.value} not found')
                if 'Users' in member.ref:
                    if not self.context.userdb.user_exists(scim_id=str(member.value)):
                        self.context.logger.error(f'User {member.value} not found')
                        raise BadRequest(detail=f'User {member.value} not found')

            db_group = self.context.groupdb.update_group(scope=scope, scim_group=group, db_group=db_group)
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


class GroupSearchResource(BaseResource):
    def on_post(self, req: Request, resp: Response):
        """
        POST /Groups/.search
        Host: scim.eduid.se
        Accept: application/scim+json

        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
            "filter": "displayName eq \"some display name\"",
        }

        HTTP/1.1 200 OK
        Content-Type: application/scim+json
        Location: https://example.com/Users/.search

        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 1,
            "Resources": [
                {
                    "displayName": "test group",
                    "id": "46aee99f-f417-41fc-97f0-1ee8970078db"
                },
            ]
        }
        """
        # TODO: Figure out scope
        scope = 'eduid.se'

        try:
            self.context.logger.info(f"Searching for group(s)")
            query: SearchRequest = SearchRequestSchema().load(req.media)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")

        match = re.match('displayName eq "(.+)"', query.filter)
        if not match:
            self.context.logger.error(f'Unrecognised filter: {query.filter}')
            raise BadRequest(detail="Unrecognised filter")

        display_name = match.group(1)
        self.context.logger.debug(f"Searching for group with display name {repr(display_name)}")
        db_groups = self.context.groupdb.get_group_by_property(
            scope=scope, key='display_name', value=display_name, skip=query.start_index, limit=query.count
        )

        list_response = ListResponse(total_results=len(db_groups))
        resources = []
        for db_group in db_groups:
            resources.append(
                {'id': db_group.identifier, 'displayName': db_group.display_name,}
            )
        list_response.resources = resources
        resp.media = ListResponseSchema().dump(list_response)
