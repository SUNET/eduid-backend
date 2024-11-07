import re
from datetime import datetime
from uuid import UUID

from fastapi import Request, Response

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.models.scim_base import Meta, SCIMResourceType, SCIMSchema
from eduid.common.utils import make_etag
from eduid.scimapi.context_request import ScimApiContext
from eduid.scimapi.exceptions import BadRequest
from eduid.scimapi.models.group import GroupMember, GroupResponse, NutidGroupExtensionV1
from eduid.scimapi.search import SearchFilter
from eduid.userdb.scimapi import ScimApiGroup

__author__ = "lundberg"


def get_group_members(req: Request, db_group: ScimApiGroup) -> list[GroupMember]:
    members = []
    for user_member in db_group.graph.member_users:
        ref = req.app.context.url_for("Users", user_member.identifier)
        members.append(GroupMember(value=UUID(user_member.identifier), ref=ref, display=user_member.display_name))
    for group_member in db_group.graph.member_groups:
        ref = req.app.context.url_for("Groups", group_member.identifier)
        members.append(GroupMember(value=UUID(group_member.identifier), ref=ref, display=group_member.display_name))
    return members


def db_group_to_response(req: ContextRequest, resp: Response, db_group: ScimApiGroup) -> GroupResponse:
    members = get_group_members(req, db_group)
    location = req.app.context.url_for("Groups", str(db_group.scim_id))
    meta = Meta(
        location=location,
        last_modified=db_group.last_modified or db_group.created,
        resource_type=SCIMResourceType.GROUP,
        created=db_group.created,
        version=db_group.version,
    )
    schemas = [SCIMSchema.CORE_20_GROUP]
    nutid_group_v1 = None
    if db_group.extensions.data:
        schemas.append(SCIMSchema.NUTID_GROUP_V1)
        nutid_group_v1 = NutidGroupExtensionV1(data=db_group.extensions.data)
    group = GroupResponse(
        display_name=db_group.graph.display_name,
        members=members,
        id=db_group.scim_id,
        external_id=db_group.external_id,
        meta=meta,
        schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
        nutid_group_v1=nutid_group_v1,
    )

    resp.headers["Location"] = location
    resp.headers["ETag"] = make_etag(db_group.version)
    req.app.context.logger.debug(f"Extra debug: Response:\n{group.model_dump_json(exclude_none=True, indent=2)}")
    return group


def filter_display_name(
    req: ContextRequest,
    filter: SearchFilter,
    skip: int | None = None,
    limit: int | None = None,
) -> tuple[list[ScimApiGroup], int]:
    if filter.op != "eq":
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported operator")
    if not isinstance(filter.val, str):
        raise BadRequest(scim_type="invalidFilter", detail="Invalid displayName")

    req.app.context.logger.debug(f"Searching for group with display name {repr(filter.val)}")
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.groupdb is not None  # please mypy
    assert skip is not None  # please mypy
    assert limit is not None  # please mypy
    groups, count = req.context.groupdb.get_groups_by_property(
        key="display_name", value=filter.val, skip=skip, limit=limit
    )

    if not groups:
        return [], 0

    return groups, count


def filter_lastmodified(
    req: ContextRequest, filter: SearchFilter, skip: int | None = None, limit: int | None = None
) -> tuple[list[ScimApiGroup], int]:
    if filter.op not in ["gt", "ge"]:
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported operator")
    if not isinstance(filter.val, str):
        raise BadRequest(scim_type="invalidFilter", detail="Invalid datetime")
    try:
        _parsed = datetime.fromisoformat(filter.val)
    except Exception:
        raise BadRequest(scim_type="invalidFilter", detail="Invalid datetime")
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.groupdb is not None  # please mypy
    return req.context.groupdb.get_groups_by_last_modified(operator=filter.op, value=_parsed, skip=skip, limit=limit)


def filter_extensions_data(
    req: ContextRequest,
    filter: SearchFilter,
    skip: int | None = None,
    limit: int | None = None,
) -> tuple[list[ScimApiGroup], int]:
    if filter.op != "eq":
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported operator")

    match = re.match(r"^extensions\.data\.([a-z_]+)$", filter.attr)
    if not match:
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported extension search key")

    req.app.context.logger.debug(f"Searching for groups with {filter.attr} {filter.op} {repr(filter.val)}")
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.groupdb is not None  # please mypy
    assert skip is not None  # please mypy
    assert limit is not None  # please mypy
    groups, count = req.context.groupdb.get_groups_by_property(
        key=filter.attr, value=filter.val, skip=skip, limit=limit
    )
    return groups, count
