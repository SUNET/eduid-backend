import re
from datetime import datetime
from typing import List, Optional, Tuple
from uuid import UUID

from falcon import HTTP_201, HTTP_204, Request, Response
from marshmallow.exceptions import ValidationError

from eduid.scimapi.db.eventdb import EventLevel, EventStatus, add_api_event
from eduid.scimapi.db.groupdb import ScimApiGroup
from eduid.scimapi.exceptions import BadRequest, NotFound
from eduid.scimapi.middleware import ctx_groupdb, ctx_userdb
from eduid.scimapi.resources.base import BaseResource, SCIMResource
from eduid.scimapi.schemas.group import (
    GroupCreateRequestSchema,
    GroupMember,
    GroupResponse,
    GroupResponseSchema,
    GroupUpdateRequestSchema,
    NutidGroupExtensionV1,
)
from eduid.scimapi.schemas.scimbase import (
    ListResponse,
    ListResponseSchema,
    Meta,
    SCIMResourceType,
    SCIMSchema,
    SearchRequest,
    SearchRequestSchema,
)
from eduid.scimapi.search import SearchFilter, parse_search_filter
from eduid.scimapi.utils import make_etag


class GroupsResource(SCIMResource):
    def _get_group_members(self, db_group: ScimApiGroup) -> List[GroupMember]:
        members = []
        for user_member in db_group.graph.member_users:
            ref = self.url_for("Users", user_member.identifier)
            members.append(GroupMember(value=UUID(user_member.identifier), ref=ref, display=user_member.display_name))
        for group_member in db_group.graph.member_groups:
            ref = self.url_for("Groups", group_member.identifier)
            members.append(GroupMember(value=UUID(group_member.identifier), ref=ref, display=group_member.display_name))
        return members

    def _db_group_to_response(self, resp: Response, db_group: ScimApiGroup) -> None:
        members = self._get_group_members(db_group)
        location = self.url_for("Groups", str(db_group.scim_id))
        meta = Meta(
            location=location,
            last_modified=db_group.last_modified or db_group.created,
            resource_type=SCIMResourceType.GROUP,
            created=db_group.created,
            version=db_group.version,
        )
        schemas = [SCIMSchema.CORE_20_GROUP]
        if db_group.extensions.data:
            schemas.append(SCIMSchema.NUTID_GROUP_V1)
        group = GroupResponse(
            display_name=db_group.graph.display_name,
            members=members,
            id=db_group.scim_id,
            meta=meta,
            schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
            nutid_group_v1=NutidGroupExtensionV1(data=db_group.extensions.data),
        )

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_group.version))
        dumped_group = GroupResponseSchema().dump(group)
        if SCIMSchema.NUTID_GROUP_V1 not in group.schemas and SCIMSchema.NUTID_GROUP_V1.value in dumped_group:
            # Serialization will always put the NUTID_GROUP_V1 in the dumped_group, even if there was no data
            del dumped_group[SCIMSchema.NUTID_GROUP_V1.value]
        resp.media = dumped_group

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

            db_group = ctx_groupdb(req).get_group_by_scim_id(scim_id)
            self.context.logger.debug(f'Found group: {db_group}')
            if not db_group:
                raise NotFound(detail="Group not found")
            self._db_group_to_response(resp, db_group)
            return

        # Return all Groups for scope
        db_groups = ctx_groupdb(req).get_groups()
        resources = []
        for db_group in db_groups:
            resources.append({'id': str(db_group.scim_id), 'displayName': db_group.graph.display_name})
        list_response = ListResponse(total_results=len(db_groups), resources=resources)
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
        self.context.logger.info('Updating group')
        try:
            update_request = GroupUpdateRequestSchema().load(req.media)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")
        self.context.logger.debug(update_request)
        if scim_id != str(update_request.id):
            self.context.logger.error(f'Id mismatch')
            self.context.logger.debug(f'{scim_id} != {update_request.id}')
            raise BadRequest(detail='Id mismatch')

        self.context.logger.info(f"Fetching group {scim_id}")
        db_group = ctx_groupdb(req).get_group_by_scim_id(str(update_request.id))
        self.context.logger.debug(f'Found group: {db_group}')
        if not db_group:
            raise NotFound(detail="Group not found")

        # Check version
        if not self._check_version(req, db_group):
            raise BadRequest(detail="Version mismatch")

        # Check that members exists in their respective db
        self.context.logger.info(f'Checking if group and user members exists')
        for member in update_request.members:
            if member.is_group:
                if not ctx_groupdb(req).group_exists(str(member.value)):
                    self.context.logger.error(f'Group {member.value} not found')
                    raise BadRequest(detail=f'Group {member.value} not found')
            if member.is_user:
                if not ctx_userdb(req).user_exists(scim_id=str(member.value)):
                    self.context.logger.error(f'User {member.value} not found')
                    raise BadRequest(detail=f'User {member.value} not found')

        updated_group, changed = ctx_groupdb(req).update_group(update_request=update_request, db_group=db_group)
        # Load the group from the database to ensure results are consistent with subsequent GETs.
        # For example, timestamps have higher resolution in updated_group than after a load.
        db_group = ctx_groupdb(req).get_group_by_scim_id(str(updated_group.scim_id))
        assert db_group  # please mypy

        if changed:
            add_api_event(
                context=self.context,
                data_owner=req.context['data_owner'],
                db_obj=db_group,
                resource_type=SCIMResourceType.GROUP,
                level=EventLevel.INFO,
                status=EventStatus.UPDATED,
                message='Group was updated',
            )

        self._db_group_to_response(resp, db_group)

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
        self.context.logger.info('Creating group')
        try:
            create_request = GroupCreateRequestSchema().load(req.media)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")
        self.context.logger.debug(create_request)
        created_group = ctx_groupdb(req).create_group(create_request=create_request)
        # Load the group from the database to ensure results are consistent with subsequent GETs.
        # For example, timestamps have higher resolution in created_group than after a load.
        db_group = ctx_groupdb(req).get_group_by_scim_id(str(created_group.scim_id))
        assert db_group  # please mypy

        add_api_event(
            context=self.context,
            data_owner=req.context['data_owner'],
            db_obj=db_group,
            resource_type=SCIMResourceType.GROUP,
            level=EventLevel.INFO,
            status=EventStatus.CREATED,
            message='Group was created',
        )

        self._db_group_to_response(resp, db_group)
        resp.status = HTTP_201

    def on_delete(self, req: Request, resp: Response, scim_id: str):
        self.context.logger.info(f'Deleting group {scim_id}')
        db_group = ctx_groupdb(req).get_group_by_scim_id(scim_id=scim_id)
        self.context.logger.debug(f'Found group: {db_group}')
        if not db_group:
            raise NotFound(detail="Group not found")

        # Check version
        if not self._check_version(req, db_group):
            raise BadRequest(detail="Version mismatch")

        res = ctx_groupdb(req).remove_group(db_group)

        add_api_event(
            context=self.context,
            data_owner=req.context['data_owner'],
            db_obj=db_group,
            resource_type=SCIMResourceType.GROUP,
            level=EventLevel.INFO,
            status=EventStatus.DELETED,
            message='Group was deleted',
        )

        self.context.logger.debug(f'Remove group result: {res}')
        resp.status = HTTP_204


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
        self.context.logger.info('Searching for group(s)')
        try:
            query: SearchRequest = SearchRequestSchema().load(req.media)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")

        filter = parse_search_filter(query.filter)

        if filter.attr == 'displayname':
            groups, total_count = self._filter_display_name(req, filter, skip=query.start_index - 1, limit=query.count)
        elif filter.attr == 'meta.lastmodified':
            groups, total_count = self._filter_lastmodified(req, filter, skip=query.start_index - 1, limit=query.count)
        elif filter.attr.startswith('extensions.data.'):
            groups, total_count = self._filter_extensions_data(
                req, filter, skip=query.start_index - 1, limit=query.count
            )
        else:
            raise BadRequest(scim_type='invalidFilter', detail=f'Can\'t filter on attribute {filter.attr}')

        resources = []
        for this in groups:
            resources.append({'id': str(this.scim_id), 'displayName': this.display_name})
        list_response = ListResponse(total_results=total_count, resources=resources)
        resp.media = ListResponseSchema().dump(list_response)

    def _filter_display_name(
        self, req: Request, filter: SearchFilter, skip: Optional[int] = None, limit: Optional[int] = None,
    ) -> Tuple[List[ScimApiGroup], int]:
        if filter.op != 'eq':
            raise BadRequest(scim_type='invalidFilter', detail='Unsupported operator')
        if not isinstance(filter.val, str):
            raise BadRequest(scim_type='invalidFilter', detail='Invalid displayName')

        self.context.logger.debug(f'Searching for group with display name {repr(filter.val)}')
        groups, count = ctx_groupdb(req).get_groups_by_property(
            key='display_name', value=filter.val, skip=skip, limit=limit
        )

        if not groups:
            return [], 0

        return groups, count

    @staticmethod
    def _filter_lastmodified(
        req: Request, filter: SearchFilter, skip: Optional[int] = None, limit: Optional[int] = None
    ) -> Tuple[List[ScimApiGroup], int]:
        if filter.op not in ['gt', 'ge']:
            raise BadRequest(scim_type='invalidFilter', detail='Unsupported operator')
        if not isinstance(filter.val, str):
            raise BadRequest(scim_type='invalidFilter', detail='Invalid datetime')
        try:
            _parsed = datetime.fromisoformat(filter.val)
        except:
            raise BadRequest(scim_type='invalidFilter', detail='Invalid datetime')
        return ctx_groupdb(req).get_groups_by_last_modified(operator=filter.op, value=_parsed, skip=skip, limit=limit)

    def _filter_extensions_data(
        self, req: Request, filter: SearchFilter, skip: Optional[int] = None, limit: Optional[int] = None,
    ) -> Tuple[List[ScimApiGroup], int]:
        if filter.op != 'eq':
            raise BadRequest(scim_type='invalidFilter', detail='Unsupported operator')

        match = re.match(r'^extensions\.data\.([a-z_]+)$', filter.attr)
        if not match:
            raise BadRequest(scim_type='invalidFilter', detail='Unsupported extension search key')

        self.context.logger.debug(f'Searching for groups with {filter.attr} {filter.op} {repr(filter.val)}')
        groups, count = ctx_groupdb(req).get_groups_by_property(
            key=filter.attr, value=filter.val, skip=skip, limit=limit
        )
        return groups, count
