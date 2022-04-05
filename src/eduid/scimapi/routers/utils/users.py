from dataclasses import asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from fastapi import Response
from pymongo.errors import DuplicateKeyError

from eduid.scimapi.context_request import ContextRequest
from eduid.scimapi.db.userdb import ScimApiUser
from eduid.scimapi.exceptions import BadRequest
from eduid.scimapi.models.scimbase import Email, Meta, Name, PhoneNumber, SCIMResourceType, SCIMSchema, SearchRequest
from eduid.scimapi.models.user import Group, LinkedAccount, NutidUserExtensionV1, Profile, UserResponse
from eduid.scimapi.search import SearchFilter
from eduid.scimapi.utils import make_etag


def get_user_groups(req: ContextRequest, db_user: ScimApiUser) -> List[Group]:
    """Return the groups for a user formatted as SCIM search sub-resources"""
    user_groups = req.context.groupdb.get_groups_for_user_identifer(db_user.scim_id)
    groups = []
    for group in user_groups:
        ref = req.app.context.url_for("Groups", group.scim_id)
        groups.append(Group(value=group.scim_id, ref=ref, display=group.display_name))
    return groups


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
    req.app.context.logger.debug(f'Extra debug: Response:\n{user.json(exclude_none=True, indent=2)}')
    return user


def save_user(req: ContextRequest, db_user: ScimApiUser) -> None:
    try:
        req.context.userdb.save(db_user)
    except DuplicateKeyError as e:
        if 'external-id' in e.details['errmsg']:
            raise BadRequest(detail='externalID must be unique')
        raise BadRequest(detail='Duplicated key error')


def acceptable_linked_accounts(value: List[LinkedAccount]):
    """
    Setting linked_accounts through SCIM might very well be forbidden in the future,
    but for now we allow setting a very limited value, to try out MFA step up using this.
    """
    for this in value:
        if this.issuer not in ['eduid.se', 'dev.eduid.se']:
            return False
        if not this.value.endswith('@dev.eduid.se'):
            return False
        for param in this.parameters:
            if param not in ['mfa_stepup']:
                return False
            if not isinstance(this.parameters[param], bool):
                return False
    return True


def users_to_resources_dicts(query: SearchRequest, users: Sequence[ScimApiUser]) -> List[Dict[str, Any]]:
    _attributes = query.attributes
    # TODO: include the requested attributes, not just id
    return [{'id': str(user.scim_id)} for user in users]


def filter_externalid(req: ContextRequest, filter: SearchFilter) -> List[ScimApiUser]:
    if filter.op != 'eq':
        raise BadRequest(scim_type='invalidFilter', detail='Unsupported operator')
    if not isinstance(filter.val, str):
        raise BadRequest(scim_type='invalidFilter', detail='Invalid externalId')

    user = req.context.userdb.get_user_by_external_id(filter.val)

    if not user:
        return []

    return [user]


def filter_lastmodified(
    req: ContextRequest, filter: SearchFilter, skip: Optional[int] = None, limit: Optional[int] = None
) -> Tuple[List[ScimApiUser], int]:
    if filter.op not in ['gt', 'ge']:
        raise BadRequest(scim_type='invalidFilter', detail='Unsupported operator')
    if not isinstance(filter.val, str):
        raise BadRequest(scim_type='invalidFilter', detail='Invalid datetime')
    return req.context.userdb.get_users_by_last_modified(
        operator=filter.op, value=datetime.fromisoformat(filter.val), skip=skip, limit=limit
    )
