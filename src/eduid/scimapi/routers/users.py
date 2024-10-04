import pprint
import re
from dataclasses import replace

from fastapi import Response

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.models.scim_base import ListResponse, SCIMResourceType, SCIMSchema, SearchRequest
from eduid.common.models.scim_user import UserCreateRequest, UserResponse, UserUpdateRequest
from eduid.scimapi.api_router import APIRouter
from eduid.scimapi.context_request import ScimApiContext, ScimApiRoute
from eduid.scimapi.exceptions import BadRequest, Conflict, ErrorDetail, MaxRetriesReached, NotFound
from eduid.scimapi.routers.utils.events import add_api_event
from eduid.scimapi.routers.utils.users import (
    acceptable_linked_accounts,
    db_user_to_response,
    filter_externalid,
    filter_lastmodified,
    filter_profile_data,
    remove_user_from_all_groups,
    save_user,
    users_to_resources_dicts,
)
from eduid.scimapi.search import parse_search_filter
from eduid.userdb.scimapi import (
    EventLevel,
    EventStatus,
    ScimApiEmail,
    ScimApiLinkedAccount,
    ScimApiName,
    ScimApiPhoneNumber,
)
from eduid.userdb.scimapi.userdb import ScimApiProfile, ScimApiUser

users_router = APIRouter(
    route_class=ScimApiRoute,
    prefix="/Users",
    responses={
        400: {"description": "Bad request", "model": ErrorDetail},
        404: {"description": "Not found", "model": ErrorDetail},
        500: {"description": "Internal server error", "model": ErrorDetail},
    },
)


@users_router.get("/{scim_id}", response_model=UserResponse, response_model_exclude_none=True)
async def on_get(req: ContextRequest, resp: Response, scim_id: str | None = None) -> UserResponse:
    if scim_id is None:
        raise BadRequest(detail="Not implemented")
    req.app.context.logger.info(f"Fetching user {scim_id}")
    assert isinstance(req.context, ScimApiContext)
    assert req.context.userdb is not None
    db_user = req.context.userdb.get_user_by_scim_id(scim_id)
    if not db_user:
        raise NotFound(detail="User not found")

    return db_user_to_response(req=req, resp=resp, db_user=db_user)


@users_router.put("/{scim_id}", response_model=UserResponse, response_model_exclude_none=True)
async def on_put(req: ContextRequest, resp: Response, update_request: UserUpdateRequest, scim_id: str) -> UserResponse:
    req.app.context.logger.info(f"Updating user {scim_id}")
    req.app.context.logger.debug(update_request)
    if scim_id != str(update_request.id):
        req.app.context.logger.error("Id mismatch")
        req.app.context.logger.debug(f"{scim_id} != {update_request.id}")
        raise BadRequest(detail="Id mismatch")

    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.userdb is not None  # please mypy
    db_user = req.context.userdb.get_user_by_scim_id(scim_id)
    if not db_user:
        raise NotFound(detail="User not found")

    # Check version
    if not req.app.context.check_version(req, db_user):
        raise BadRequest(detail="Version mismatch")

    req.app.context.logger.debug(
        f"Extra debug: db_user BEFORE {scim_id} as dict:\n{pprint.pformat(db_user.to_dict(), width=120)}"
    )

    core_changed = False
    if SCIMSchema.CORE_20_USER in update_request.schemas:
        name_in = ScimApiName(**update_request.name.dict(exclude_none=True))
        emails_in = {ScimApiEmail(**email.dict()) for email in update_request.emails}
        phone_numbers_in = {ScimApiPhoneNumber(**number.dict()) for number in update_request.phone_numbers}
        # external_id
        if update_request.external_id != db_user.external_id:
            db_user = replace(db_user, external_id=update_request.external_id)
            core_changed = True
        # preferred_language
        if update_request.preferred_language != db_user.preferred_language:
            db_user = replace(db_user, preferred_language=update_request.preferred_language)
            core_changed = True
        # name
        if name_in != db_user.name:
            db_user = replace(db_user, name=name_in)
            core_changed = True
        # emails
        if emails_in != set(db_user.emails):
            db_user = replace(db_user, emails=list(emails_in))
            core_changed = True
        # phone_numbers
        if phone_numbers_in != set(db_user.phone_numbers):
            db_user = replace(db_user, phone_numbers=list(phone_numbers_in))
            core_changed = True

    nutid_changed = False
    if SCIMSchema.NUTID_USER_V1 in update_request.schemas and update_request.nutid_user_v1 is not None:
        if not acceptable_linked_accounts(update_request.nutid_user_v1.linked_accounts, req.app.config.environment):
            raise BadRequest(detail="Invalid nutid linked_accounts")

        # Look for changes in profiles
        for this in update_request.nutid_user_v1.profiles.keys():
            if this not in db_user.profiles:
                req.app.context.logger.info(
                    f"Adding profile {this}/{update_request.nutid_user_v1.profiles[this]} to user"
                )
                nutid_changed = True
            elif update_request.nutid_user_v1.profiles[this].to_dict() != db_user.profiles[this].to_dict():
                req.app.context.logger.info(f"Profile {this}/{update_request.nutid_user_v1.profiles[this]} updated")
                nutid_changed = True
            else:
                req.app.context.logger.info(f"Profile {this}/{update_request.nutid_user_v1.profiles[this]} not changed")
        for this in db_user.profiles.keys():
            if this not in update_request.nutid_user_v1.profiles:
                req.app.context.logger.info(f"Profile {this}/{db_user.profiles[this]} removed")
                nutid_changed = True

        if nutid_changed:
            for profile_name, profile in update_request.nutid_user_v1.profiles.items():
                db_profile = ScimApiProfile(attributes=profile.attributes, data=profile.data)
                db_user.profiles[profile_name] = db_profile

        # convert from one type of linked accounts to another
        _db_linked_accounts = [
            ScimApiLinkedAccount(issuer=x.issuer, value=x.value, parameters=x.parameters)
            for x in update_request.nutid_user_v1.linked_accounts
        ]

        # Look for changes in linked_accounts
        if sorted(_db_linked_accounts, key=lambda x: x.value) != sorted(db_user.linked_accounts, key=lambda x: x.value):
            db_user.linked_accounts = _db_linked_accounts
            req.app.context.logger.info(f"Updated linked_accounts: {db_user.linked_accounts}")
            nutid_changed = True

    req.app.context.logger.debug(f"Core changed: {core_changed}, nutid_changed: {nutid_changed}")
    if core_changed or nutid_changed:
        assert req.context.data_owner is not None  # please mypy
        save_user(req, db_user)
        add_api_event(
            context=req.app.context,
            data_owner=req.context.data_owner,
            db_obj=db_user,
            resource_type=SCIMResourceType.USER,
            level=EventLevel.INFO,
            status=EventStatus.UPDATED,
            message="User was updated",
        )
    else:
        req.app.context.logger.info("No changes detected")

    return db_user_to_response(req=req, resp=resp, db_user=db_user)


@users_router.post("/", response_model=UserResponse, response_model_exclude_none=True)
async def on_post(req: ContextRequest, resp: Response, create_request: UserCreateRequest) -> UserResponse:
    """
    POST /Users  HTTP/1.1
    Host: example.com
    Accept: application/scim+json
    Content-Type: application/scim+json
    Authorization: Bearer h480djs93hd8
    Content-Length: ...

    {
      "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
      "userName":"bjensen",
      "externalId":"bjensen",
      "name":{
        "formatted":"Ms. Barbara J Jensen III",
        "familyName":"Jensen",
        "givenName":"Barbara"
      }
    }


    HTTP/1.1 201 Created
    Content-Type: application/scim+json
    Location:
     https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646
    ETag: W/"e180ee84f0671b1"

    {
      "schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id":"2819c223-7f76-453a-919d-413861904646",
      "externalId":"bjensen",
      "meta":{
        "resourceType":"User",
        "created":"2011-08-01T21:32:44.882Z",
        "lastModified":"2011-08-01T21:32:44.882Z",
        "location":
    "https://example.com/v2/Users/2819c223-7f76-453a-919d-413861904646",
        "version":"W\\/\"e180ee84f0671b1\""
      },
      "name":{
        "formatted":"Ms. Barbara J Jensen III",
        "familyName":"Jensen",
        "givenName":"Barbara"
      },
      "userName":"bjensen"
    }
    """

    req.app.context.logger.info("Creating user")
    req.app.context.logger.debug(create_request)

    profiles = {}
    linked_accounts = []
    if SCIMSchema.NUTID_USER_V1 in create_request.schemas and create_request.nutid_user_v1 is not None:
        if not acceptable_linked_accounts(create_request.nutid_user_v1.linked_accounts, req.app.config.environment):
            raise BadRequest(detail="Invalid nutid linked_accounts")

        # convert from one type of profiles to another
        for profile_name, profile in create_request.nutid_user_v1.profiles.items():
            profiles[profile_name] = ScimApiProfile(attributes=profile.attributes, data=profile.data)

        # convert from one type of linked accounts to another
        linked_accounts = [
            ScimApiLinkedAccount(issuer=x.issuer, value=x.value, parameters=x.parameters)
            for x in create_request.nutid_user_v1.linked_accounts
        ]

    db_user = ScimApiUser(
        external_id=create_request.external_id,
        name=ScimApiName(**create_request.name.dict()),
        emails=[ScimApiEmail(**email.dict()) for email in create_request.emails],
        phone_numbers=[ScimApiPhoneNumber(**number.dict()) for number in create_request.phone_numbers],
        preferred_language=create_request.preferred_language,
        profiles=profiles,
        linked_accounts=linked_accounts,
    )

    save_user(req, db_user)
    assert isinstance(req.context, ScimApiContext)  # please mypy
    assert req.context.data_owner is not None  # please mypy
    add_api_event(
        context=req.app.context,
        data_owner=req.context.data_owner,
        db_obj=db_user,
        resource_type=SCIMResourceType.USER,
        level=EventLevel.INFO,
        status=EventStatus.CREATED,
        message="User was created",
    )

    user = db_user_to_response(req=req, resp=resp, db_user=db_user)
    resp.status_code = 201
    return user


@users_router.delete(
    "/{scim_id}",
    status_code=204,
    responses={204: {"description": "No Content"}},
)
async def on_delete(req: ContextRequest, scim_id: str) -> None:
    assert isinstance(req.context, ScimApiContext)  # please mypy
    req.app.context.logger.info(f"Deleting user {scim_id}")
    assert req.context.userdb is not None  # please mypy
    db_user = req.context.userdb.get_user_by_scim_id(scim_id=scim_id)
    req.app.context.logger.debug(f"Found user: {db_user}")
    if not db_user:
        raise NotFound(detail="User not found")

    # Check version
    if not req.app.context.check_version(req, db_user):
        raise BadRequest(detail="Version mismatch")

    try:
        remove_user_from_all_groups(req, db_user)
    except MaxRetriesReached:
        # this can be a problem when deleting many users that are all part of the same group as it can
        # lead to a race condition where the group is updated before the user is removed from it
        req.app.context.logger.exception("Max retries reached when removing user from groups")
        raise Conflict(detail="Database object out of sync, please retry")

    res = req.context.userdb.remove(db_user)

    assert req.context.data_owner is not None  # please mypy
    add_api_event(
        context=req.app.context,
        data_owner=req.context.data_owner,
        db_obj=db_user,
        resource_type=SCIMResourceType.USER,
        level=EventLevel.INFO,
        status=EventStatus.DELETED,
        message="User was deleted",
    )

    req.app.context.logger.debug(f"Remove user result: {res}")


@users_router.post("/.search", response_model=ListResponse, response_model_exclude_none=True)
async def search(req: ContextRequest, query: SearchRequest) -> ListResponse:
    """
    POST /Users/.search
    Host: scim.eduid.se
    Accept: application/scim+json

    {
      "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
      "attributes": ["givenName", "familyName"],
      "filter": "id eq \"takaj-jorar\"",
      "startIndex": 1,
      "count": 1
    }



    HTTP/1.1 200 OK
    Content-Type: application/scim+json
    Location: https://example.com/Users/.search

    {
      "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      "totalResults": 1,
      "itemsPerPage": 1,
      "startIndex": 1,
      "Resources": [
        {
          "givenName": "Kim",
          "familyName": "Svensson"
        }
      ]
    }
    """
    req.app.context.logger.info("Searching for users(s)")
    req.app.context.logger.debug(f"Parsed user search query: {query}")

    _filter = parse_search_filter(query.filter)
    profile_data_regex = re.compile(r"^profiles\.([a-z_]+)\.data\.([a-z_]+)$")

    if _filter.attr == "externalid":
        users = filter_externalid(req, _filter)
        total_count = len(users)
    elif _filter.attr == "meta.lastmodified":
        # SCIM start_index 1 equals item 0
        users, total_count = filter_lastmodified(req, _filter, skip=query.start_index - 1, limit=query.count)
    elif _filter.attr.startswith("profiles.") and (
        re_match := re.match(pattern=profile_data_regex, string=_filter.attr)
    ):
        users, total_count = filter_profile_data(
            req,
            _filter,
            profile=re_match.group(1),
            key=re_match.group(2),
            skip=query.start_index - 1,
            limit=query.count,
        )
    else:
        raise BadRequest(scim_type="invalidFilter", detail=f"Can't filter on attribute {_filter.attr}")

    return ListResponse(resources=users_to_resources_dicts(query, users), total_results=total_count)
