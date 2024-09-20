from fastapi import Response

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.models.scim_base import ListResponse, SCIMResourceType, SearchRequest
from eduid.scimapi.api_router import APIRouter
from eduid.scimapi.context_request import ScimApiRoute
from eduid.scimapi.exceptions import BadRequest, ErrorDetail, NotFound
from eduid.scimapi.models.group import GroupCreateRequest, GroupResponse, GroupUpdateRequest
from eduid.scimapi.routers.utils.events import add_api_event
from eduid.scimapi.routers.utils.groups import (
    db_group_to_response,
    filter_display_name,
    filter_extensions_data,
    filter_lastmodified,
)
from eduid.scimapi.search import parse_search_filter
from eduid.userdb.scimapi import EventLevel, EventStatus

groups_router = APIRouter(
    route_class=ScimApiRoute,
    prefix="/Groups",
    responses={
        400: {"description": "Bad request", "model": ErrorDetail},
        404: {"description": "Not found", "model": ErrorDetail},
        500: {"description": "Internal server error", "model": ErrorDetail},
    },
)


@groups_router.get("/", response_model=ListResponse)
async def on_get_all(req: ContextRequest) -> ListResponse:
    db_groups = req.context.groupdb.get_groups()
    resources = [{"id": str(db_group.scim_id), "displayName": db_group.graph.display_name} for db_group in db_groups]
    return ListResponse(total_results=len(db_groups), resources=resources)


@groups_router.get("/{scim_id}", response_model=GroupResponse, response_model_exclude_none=True)
async def on_get_one(req: ContextRequest, resp: Response, scim_id: str) -> GroupResponse:
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
    req.app.context.logger.info(f"Fetching group {scim_id}")

    db_group = req.context.groupdb.get_group_by_scim_id(scim_id)
    req.app.context.logger.debug(f"Found group: {db_group}")
    if not db_group:
        raise NotFound(detail="Group not found")
    return db_group_to_response(req, resp, db_group)


@groups_router.put("/{scim_id}", response_model=GroupResponse, response_model_exclude_none=True)
async def on_put(
    req: ContextRequest, resp: Response, scim_id: str, update_request: GroupUpdateRequest
) -> GroupResponse:
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
    req.app.context.logger.info("Updating group")
    req.app.context.logger.debug(update_request)
    if scim_id != str(update_request.id):
        req.app.context.logger.error("Id mismatch")
        req.app.context.logger.debug(f"{scim_id} != {update_request.id}")
        raise BadRequest(detail="Id mismatch")

    req.app.context.logger.info(f"Fetching group {scim_id}")
    db_group = req.context.groupdb.get_group_by_scim_id(str(update_request.id))
    req.app.context.logger.debug(f"Found group: {db_group}")
    if not db_group:
        raise NotFound(detail="Group not found")

    # Check version
    if not req.app.context.check_version(req, db_group):
        raise BadRequest(detail="Version mismatch")

    # Check that members exists in their respective db
    req.app.context.logger.info("Checking if group and user members exists")
    for member in update_request.members:
        if member.is_group:
            if not req.context.groupdb.group_exists(str(member.value)):
                req.app.context.logger.error(f"Group {member.value} not found")
                raise BadRequest(detail=f"Group {member.value} not found")
        if member.is_user:
            if not req.context.userdb.user_exists(scim_id=str(member.value)):
                req.app.context.logger.error(f"User {member.value} not found")
                raise BadRequest(detail=f"User {member.value} not found")

    updated_group, changed = req.context.groupdb.update_group(update_request=update_request, db_group=db_group)
    # Load the group from the database to ensure results are consistent with subsequent GETs.
    # For example, timestamps have higher resolution in updated_group than after a load.
    db_group = req.context.groupdb.get_group_by_scim_id(str(updated_group.scim_id))
    assert db_group  # please mypy

    if changed:
        add_api_event(
            context=req.app.context,
            data_owner=req.context.data_owner,
            db_obj=db_group,
            resource_type=SCIMResourceType.GROUP,
            level=EventLevel.INFO,
            status=EventStatus.UPDATED,
            message="Group was updated",
        )

    return db_group_to_response(req, resp, db_group)


@groups_router.post("/", response_model=GroupResponse, response_model_exclude_none=True)
async def on_post(req: ContextRequest, resp: Response, create_request: GroupCreateRequest) -> GroupResponse:
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
    req.app.context.logger.info("Creating group")
    req.app.context.logger.debug(create_request)
    created_group = req.context.groupdb.create_group(create_request=create_request)
    # Load the group from the database to ensure results are consistent with subsequent GETs.
    # For example, timestamps have higher resolution in created_group than after a load.
    db_group = req.context.groupdb.get_group_by_scim_id(str(created_group.scim_id))
    assert db_group  # please mypy

    add_api_event(
        context=req.app.context,
        data_owner=req.context.data_owner,
        db_obj=db_group,
        resource_type=SCIMResourceType.GROUP,
        level=EventLevel.INFO,
        status=EventStatus.CREATED,
        message="Group was created",
    )

    group_response = db_group_to_response(req, resp, db_group)
    resp.status_code = 201
    return group_response


@groups_router.delete(
    "/{scim_id}",
    status_code=204,
    responses={204: {"description": "No Content"}},
)
async def on_delete(req: ContextRequest, scim_id: str) -> None:
    req.app.context.logger.info(f"Deleting group {scim_id}")
    db_group = req.context.groupdb.get_group_by_scim_id(scim_id=scim_id)
    req.app.context.logger.debug(f"Found group: {db_group}")
    if not db_group:
        raise NotFound(detail="Group not found")

    # Check version
    if not req.app.context.check_version(req, db_group):
        raise BadRequest(detail="Version mismatch")

    res = req.context.groupdb.remove_group(db_group)

    add_api_event(
        context=req.app.context,
        data_owner=req.context.data_owner,
        db_obj=db_group,
        resource_type=SCIMResourceType.GROUP,
        level=EventLevel.INFO,
        status=EventStatus.DELETED,
        message="Group was deleted",
    )

    req.app.context.logger.debug(f"Remove group result: {res}")


@groups_router.post("/.search", response_model=ListResponse, response_model_exclude_none=True)
async def search(req: ContextRequest, query: SearchRequest) -> ListResponse:
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
    req.app.context.logger.info("Searching for group(s)")
    _filter = parse_search_filter(query.filter)

    if _filter.attr == "displayname":
        groups, total_count = filter_display_name(req, _filter, skip=query.start_index - 1, limit=query.count)
    elif _filter.attr == "meta.lastmodified":
        groups, total_count = filter_lastmodified(req, _filter, skip=query.start_index - 1, limit=query.count)
    elif _filter.attr.startswith("extensions.data."):
        groups, total_count = filter_extensions_data(req, _filter, skip=query.start_index - 1, limit=query.count)
    else:
        raise BadRequest(scim_type="invalidFilter", detail=f"Can't filter on attribute {_filter.attr}")

    resources = [{"id": str(this.scim_id), "displayName": this.display_name} for this in groups]

    return ListResponse(total_results=total_count, resources=resources)
