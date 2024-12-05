from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime
from typing import Any

from fastapi import Response
from pymongo.errors import DuplicateKeyError

from eduid.common.config.base import EduidEnvironment
from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.models.scim_base import Email, Meta, Name, PhoneNumber, SCIMResourceType, SCIMSchema, SearchRequest
from eduid.common.models.scim_user import Group, LinkedAccount, NutidUserExtensionV1, Profile, UserResponse
from eduid.common.utils import make_etag
from eduid.scimapi.context_request import ScimApiContext
from eduid.scimapi.exceptions import BadRequest
from eduid.scimapi.routers.utils.events import add_api_event
from eduid.scimapi.search import SearchFilter
from eduid.scimapi.utils import retryable_db_write
from eduid.userdb.scimapi import EventLevel, EventStatus
from eduid.userdb.scimapi.userdb import ScimApiUser


def get_user_groups(req: ContextRequest, db_user: ScimApiUser) -> list[Group]:
    """Return the groups for a user formatted as SCIM search sub-resources"""
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.groupdb is not None  # please mypy
    user_groups = req.context.groupdb.get_groups_for_user_identifer(db_user.scim_id)
    groups = []
    for group in user_groups:
        ref = req.app.context.url_for("Groups", group.scim_id)
        groups.append(Group(value=group.scim_id, ref=ref, display=group.display_name))
    return groups


@retryable_db_write
def remove_user_from_all_groups(req: ContextRequest, db_user: ScimApiUser) -> None:
    """Remove a user from all groups"""
    # Remove user from groups
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.groupdb is not None  # please mypy
    assert req.context.data_owner is not None  # please mypy
    for member_group in req.context.groupdb.get_groups_for_user_identifer(db_user.scim_id):
        # we need to get the full group object to get all the members
        group = req.context.groupdb.get_group_by_scim_id(str(member_group.scim_id))
        assert group is not None
        for member in group.graph.members.copy():
            if member.identifier == str(db_user.scim_id):
                req.app.context.logger.debug(
                    f"Removing member {db_user.scim_id} from group {group.scim_id} ({group.display_name}"
                )
                group.graph.members.remove(member)
                req.context.groupdb.save(group)
                add_api_event(
                    context=req.app.context,
                    data_owner=req.context.data_owner,
                    db_obj=group,
                    resource_type=SCIMResourceType.GROUP,
                    level=EventLevel.INFO,
                    status=EventStatus.UPDATED,
                    message="Member was removed",
                )
                break

    for owner_group in req.context.groupdb.get_groups_owned_by_user_identifier(db_user.scim_id):
        for owner in owner_group.graph.owners.copy():
            if owner.identifier == str(db_user.scim_id):
                req.app.context.logger.debug(
                    f"Removing member {db_user.scim_id} from group {owner_group.scim_id} ({owner_group.display_name}"
                )
                owner_group.graph.owners.remove(owner)
                req.context.groupdb.save(owner_group)
                add_api_event(
                    context=req.app.context,
                    data_owner=req.context.data_owner,
                    db_obj=owner_group,
                    resource_type=SCIMResourceType.GROUP,
                    level=EventLevel.INFO,
                    status=EventStatus.UPDATED,
                    message="Owner was removed",
                )
                break


def db_user_to_response(req: ContextRequest, resp: Response, db_user: ScimApiUser) -> UserResponse:
    location = req.app.context.url_for("Users", db_user.scim_id)
    meta = Meta(
        location=location,
        last_modified=db_user.last_modified,
        resource_type=SCIMResourceType.USER,
        created=db_user.created,
        version=db_user.version,
    )

    schemas = [SCIMSchema.CORE_20_USER]
    nutid_user_v1 = None
    if db_user.profiles or db_user.linked_accounts:
        schemas.append(SCIMSchema.NUTID_USER_V1)

        # Convert one type of Profile into another
        _profiles = {k: Profile(attributes=v.attributes, data=v.data) for k, v in db_user.profiles.items()}

        # Convert one type of LinkedAccount into another
        _linked_accounts = [
            LinkedAccount(issuer=x.issuer, value=x.value, parameters=x.parameters) for x in db_user.linked_accounts
        ]
        nutid_user_v1 = NutidUserExtensionV1(profiles=_profiles, linked_accounts=_linked_accounts)

    user = UserResponse(
        id=db_user.scim_id,
        external_id=db_user.external_id,
        name=Name(**asdict(db_user.name)),
        emails=[Email(**asdict(email)) for email in db_user.emails],
        phone_numbers=[PhoneNumber(**asdict(number)) for number in db_user.phone_numbers],
        preferred_language=db_user.preferred_language,
        groups=get_user_groups(req=req, db_user=db_user),
        meta=meta,
        schemas=schemas,  # extra list() needed to work with _both_ mypy and marshmallow
        nutid_user_v1=nutid_user_v1,
    )

    resp.headers["Location"] = location
    resp.headers["ETag"] = make_etag(db_user.version)
    req.app.context.logger.debug(f"Extra debug: Response:\n{user.model_dump_json(exclude_none=True, indent=2)}")
    return user


def save_user(req: ContextRequest, db_user: ScimApiUser) -> None:
    try:
        assert isinstance(req.context, ScimApiContext)  # please mypy
        assert req.context.userdb is not None  # please mypy
        req.context.userdb.save(db_user)
    except DuplicateKeyError as e:
        assert e.details is not None  # please mypy
        if "external-id" in e.details["errmsg"]:
            raise BadRequest(detail="externalID must be unique")
        raise BadRequest(detail="Duplicated key error")


def acceptable_linked_accounts(value: list[LinkedAccount], environment: EduidEnvironment) -> bool:
    """
    Setting linked_accounts through SCIM with limited issuer and value. If we need to support
    stepup with someone other than eduID this needs to change.
    """
    # short circuit this check for dev env
    if environment == EduidEnvironment.dev:
        return True

    for this in value:
        if this.issuer not in ["eduid.se", "dev.eduid.se"]:
            return False
        if not this.value.endswith("eduid.se"):
            return False
        for param in this.parameters:
            if param not in ["mfa_stepup"]:
                return False
            if not isinstance(this.parameters[param], bool):
                return False
    return True


def users_to_resources_dicts(query: SearchRequest, users: Sequence[ScimApiUser]) -> list[dict[str, Any]]:
    resources = []
    for user in users:
        resource: dict[str, Any] = {"id": str(user.scim_id)}
        if query.attributes:
            # TODO: this is a hack to get some attributes we need
            if "givenName" in query.attributes:
                resource["givenName"] = user.name.given_name
            if "familyName" in query.attributes:
                resource["familyName"] = user.name.family_name
            if "formatted" in query.attributes:
                resource["formatted"] = user.name.formatted
            if "externalId" in query.attributes:
                resource["externalId"] = user.external_id
        resources.append(resource)
    return resources


def filter_externalid(req: ContextRequest, search_filter: SearchFilter) -> list[ScimApiUser]:
    if search_filter.op != "eq":
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported operator")
    if not isinstance(search_filter.val, str):
        raise BadRequest(scim_type="invalidFilter", detail="Invalid externalId")

    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.userdb is not None  # please mypy
    user = req.context.userdb.get_user_by_external_id(search_filter.val)

    if not user:
        return []

    return [user]


def filter_lastmodified(
    req: ContextRequest, search_filter: SearchFilter, skip: int | None = None, limit: int | None = None
) -> tuple[list[ScimApiUser], int]:
    if search_filter.op not in ["gt", "ge"]:
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported operator")
    if not isinstance(search_filter.val, str):
        raise BadRequest(scim_type="invalidFilter", detail="Invalid datetime")
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.userdb is not None  # please mypy
    return req.context.userdb.get_users_by_last_modified(
        operator=search_filter.op, value=datetime.fromisoformat(search_filter.val), skip=skip, limit=limit
    )


def filter_profile_data(
    req: ContextRequest,
    search_filter: SearchFilter,
    profile: str,
    key: str,
    skip: int | None = None,
    limit: int | None = None,
) -> tuple[list[ScimApiUser], int]:
    if search_filter.op != "eq":
        raise BadRequest(scim_type="invalidFilter", detail="Unsupported operator")

    req.app.context.logger.debug(
        f"Searching for users with {search_filter.attr} {search_filter.op} {repr(search_filter.val)}"
    )
    assert isinstance(req.context, ScimApiContext)
    assert req.context.userdb is not None
    users, count = req.context.userdb.get_user_by_profile_data(
        profile=profile, operator=search_filter.op, key=key, value=search_filter.val, skip=skip, limit=limit
    )
    return users, count
