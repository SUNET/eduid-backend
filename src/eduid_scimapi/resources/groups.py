import re
from typing import List, Optional
from uuid import UUID

from falcon import Request, Response
from marshmallow.exceptions import ValidationError

from eduid_groupdb.exceptions import MultipleReturnedError

from eduid_scimapi.exceptions import BadRequest, NotFound
from eduid_scimapi.group import (
    Group,
    GroupCreateRequestSchema,
    GroupMember,
    GroupResponse,
    GroupResponseSchema,
    GroupUpdateRequest,
    GroupUpdateRequestSchema,
)
from eduid_scimapi.groupdb import DBGroup
from eduid_scimapi.resources.base import BaseResource, SCIMResource
from eduid_scimapi.scimbase import (
    ListResponse,
    ListResponseSchema,
    Meta,
    SCIMResourceType,
    SCIMSchema,
    SearchRequest,
    SearchRequestSchema,
    make_etag,
)


class GroupsResource(SCIMResource):
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
            last_modified=db_group.modified_ts or db_group.created_ts,
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

        if db_group.attributes._id is not None:
            group.schemas.append(SCIMSchema.NUTID_V1)
            group.nutid_group_v1.data = db_group.attributes.data

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_group.version))
        resp.media = GroupResponseSchema().dump(group)

    def on_get(self, req: Request, resp: Response, scim_id: Optional[str] = None):
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
        if scim_id:
            self.context.logger.info(f"Fetching group {scim_id}")

            db_group = req.context['groupdb'].get_group_by_scim_id(identifier=scim_id)
            self.context.logger.debug(f'Found group: {db_group}')
            if not db_group:
                raise NotFound(detail="Group not found")
            self._db_group_to_response(resp, db_group)
        else:
            # Return all Groups for scope
            db_groups: List[DBGroup] = req.context['groupdb'].get_groups()
            list_response = ListResponse(total_results=len(db_groups))
            resources = []
            for db_group in db_groups:
                resources.append(
                    {'id': db_group.identifier, 'displayName': db_group.display_name,}
                )
            list_response.resources = resources
            resp.media = ListResponseSchema().dump(list_response)

    def on_put(self, req: Request, resp: Response, scim_id: str):
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
            update_request: GroupUpdateRequest = GroupUpdateRequestSchema().load(req.media)
            self.context.logger.debug(update_request)
            if scim_id != str(update_request.id):
                self.context.logger.error(f'Id mismatch')
                self.context.logger.debug(f'{scim_id} != {update_request.id}')
                raise BadRequest(detail='Id mismatch')

            # Please mypy as GroupUpdateRequest no longer inherit from Group
            group = Group(
                display_name=update_request.display_name,
                members=update_request.members,
                nutid_v1=update_request.nutid_v1,
            )

            self.context.logger.info(f"Fetching group {scim_id}")

            # Get group from db
            db_group: DBGroup = req.context['groupdb'].get_group_by_scim_id(identifier=str(update_request.id))
            self.context.logger.debug(f'Found group: {db_group}')
            if not db_group:
                raise NotFound(detail="Group not found")

            # Check version
            if not self._check_version(req, db_group):
                raise BadRequest(detail="Version mismatch")

            # Check that members exists in their respective db
            self.context.logger.info(f'Checking if group and user members exists')
            for member in group.members:
                if 'Groups' in member.ref:
                    if not req.context['groupdb'].group_exists(identifier=str(member.value)):
                        self.context.logger.error(f'Group {member.value} not found')
                        raise BadRequest(detail=f'Group {member.value} not found')
                if 'Users' in member.ref:
                    if not req.context['userdb'].user_exists(scim_id=str(member.value)):
                        self.context.logger.error(f'User {member.value} not found')
                        raise BadRequest(detail=f'User {member.value} not found')

            db_group = req.context['groupdb'].update_group(scim_group=group, db_group=db_group)
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
        self.context.logger.info(f"Creating group")
        try:
            group: Group = GroupCreateRequestSchema().load(req.media)
            self.context.logger.debug(group)
            db_group = req.context['groupdb'].create_group(scim_group=group)
            resp.status = '201'
            self._db_group_to_response(resp, db_group)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")

    def on_delete(self, req: Request, resp: Response, scim_id: str):
        self.context.logger.info(f"Fetching group {scim_id}")

        # Get group from db
        db_group: DBGroup = req.context['groupdb'].get_group_by_scim_id(identifier=scim_id)
        self.context.logger.debug(f'Found group: {db_group}')
        if not db_group:
            raise NotFound(detail="Group not found")

        # Check version
        if not self._check_version(req, db_group):
            raise BadRequest(detail="Version mismatch")

        req.context['groupdb'].remove_group(identifier=scim_id)
        resp.status = '204'


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
        # SCIM start_index 1 equals item 0
        db_groups = req.context['groupdb'].get_groups_by_property(
            key='display_name', value=display_name, skip=query.start_index - 1, limit=query.count
        )

        list_response = ListResponse(total_results=len(db_groups))
        resources = []
        for db_group in db_groups:
            resources.append({'id': db_group.identifier, 'displayName': db_group.display_name})
        list_response.resources = resources
        resp.media = ListResponseSchema().dump(list_response)
