import pprint
from dataclasses import asdict, replace
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

from falcon import HTTP_201, Request, Response
from marshmallow import ValidationError
from pymongo.errors import DuplicateKeyError

from eduid.scimapi.db.common import ScimApiEmail, ScimApiLinkedAccount, ScimApiName, ScimApiPhoneNumber
from eduid.scimapi.db.eventdb import EventLevel, EventStatus, add_api_event
from eduid.scimapi.db.userdb import ScimApiProfile, ScimApiUser
from eduid.scimapi.exceptions import BadRequest, NotFound
from eduid.scimapi.middleware import ctx_groupdb, ctx_userdb
from eduid.scimapi.resources.base import BaseResource, SCIMResource
from eduid.scimapi.schemas.scimbase import (
    Email,
    ListResponse,
    ListResponseSchema,
    Meta,
    Name,
    PhoneNumber,
    SCIMResourceType,
    SCIMSchema,
    SearchRequest,
    SearchRequestSchema,
)
from eduid.scimapi.schemas.user import (
    Group,
    LinkedAccount,
    NutidUserExtensionV1,
    Profile,
    UserCreateRequest,
    UserCreateRequestSchema,
    UserResponse,
    UserResponseSchema,
    UserUpdateRequest,
    UserUpdateRequestSchema,
)
from eduid.scimapi.search import SearchFilter, parse_search_filter
from eduid.scimapi.utils import make_etag


class UsersResource(SCIMResource):
    def _get_user_groups(self, req: Request, db_user: ScimApiUser) -> List[Group]:
        """ Return the groups for a user formatted as SCIM search sub-resources """
        user_groups = ctx_groupdb(req).get_groups_for_user_identifer(db_user.scim_id)
        groups = []
        for group in user_groups:
            ref = self.url_for("Groups", group.scim_id)
            groups.append(Group(value=group.scim_id, ref=ref, display=group.display_name))
        return groups

    def _db_user_to_response(self, req: Request, resp: Response, db_user: ScimApiUser):
        location = self.url_for("Users", db_user.scim_id)
        meta = Meta(
            location=location,
            last_modified=db_user.last_modified,
            resource_type=SCIMResourceType.USER,
            created=db_user.created,
            version=db_user.version,
        )

        schemas = [SCIMSchema.CORE_20_USER]
        if db_user.profiles or db_user.linked_accounts:
            schemas.append(SCIMSchema.NUTID_USER_V1)

        # Convert one type of Profile into another
        _profiles = {k: Profile(attributes=v.attributes, data=v.data) for k, v in db_user.profiles.items()}

        # Convert one type of LinkedAccount into another
        _linked_accounts = [
            LinkedAccount(issuer=x.issuer, value=x.value, parameters=x.parameters) for x in db_user.linked_accounts
        ]

        user = UserResponse(
            id=db_user.scim_id,
            external_id=db_user.external_id,
            name=Name(**asdict(db_user.name)),
            emails=[Email(**asdict(email)) for email in db_user.emails],
            phone_numbers=[PhoneNumber(**asdict(number)) for number in db_user.phone_numbers],
            preferred_language=db_user.preferred_language,
            groups=self._get_user_groups(req=req, db_user=db_user),
            meta=meta,
            schemas=list(schemas),  # extra list() needed to work with _both_ mypy and marshmallow
            nutid_user_v1=NutidUserExtensionV1(profiles=_profiles, linked_accounts=_linked_accounts),
        )

        resp.set_header("Location", location)
        resp.set_header("ETag", make_etag(db_user.version))
        resp.media = UserResponseSchema().dump(user)
        self.context.logger.debug(f'Extra debug: Response:\n{pprint.pformat(resp.media)}')

    @staticmethod
    def _save_user(req: Request, db_user: ScimApiUser) -> None:
        try:
            ctx_userdb(req).save(db_user)
        except DuplicateKeyError as e:
            if 'external-id' in e.details['errmsg']:
                raise BadRequest(detail='externalID must be unique')
            raise BadRequest(detail='Duplicated key error')

    @staticmethod
    def _comparable_linked_accounts(data: List[ScimApiLinkedAccount]) -> List[Dict[str, Any]]:
        res = [x.to_dict() for x in data]
        return sorted(res, key=lambda x: x['value'])

    def on_get(self, req: Request, resp: Response, scim_id: Optional[str] = None):
        if scim_id is None:
            raise BadRequest(detail='Not implemented')
        self.context.logger.info(f'Fetching user {scim_id}')
        db_user = ctx_userdb(req).get_user_by_scim_id(scim_id)
        if not db_user:
            raise NotFound(detail='User not found')

        self._db_user_to_response(req=req, resp=resp, db_user=db_user)

    def on_put(self, req: Request, resp: Response, scim_id):
        try:
            self.context.logger.info(f'Updating user {scim_id}')

            update_request: UserUpdateRequest = UserUpdateRequestSchema().load(req.media)
            self.context.logger.debug(update_request)
            if scim_id != str(update_request.id):
                self.context.logger.error(f'Id mismatch')
                self.context.logger.debug(f'{scim_id} != {update_request.id}')
                raise BadRequest(detail='Id mismatch')

            db_user = ctx_userdb(req).get_user_by_scim_id(scim_id)
            if not db_user:
                raise NotFound(detail="User not found")

            # Check version
            if not self._check_version(req, db_user):
                raise BadRequest(detail="Version mismatch")

            if not self._acceptable_linked_accounts(update_request.nutid_user_v1.linked_accounts):
                raise BadRequest(detail='Invalid nutid linked_accounts')

            self.context.logger.debug(f'Extra debug: db_user {scim_id} as dict:\n{pprint.pformat(db_user.to_dict())}')

            core_changed = False
            if SCIMSchema.CORE_20_USER in update_request.schemas:
                name_in = ScimApiName(**asdict(update_request.name))
                emails_in = set(ScimApiEmail(**asdict(email)) for email in update_request.emails)
                phone_numbers_in = set(ScimApiPhoneNumber(**asdict(number)) for number in update_request.phone_numbers)
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
            if SCIMSchema.NUTID_USER_V1 in update_request.schemas:
                # Look for changes in profiles
                for this in update_request.nutid_user_v1.profiles.keys():
                    if this not in db_user.profiles:
                        self.context.logger.info(
                            f'Adding profile {this}/{update_request.nutid_user_v1.profiles[this]} to user'
                        )
                        nutid_changed = True
                    elif update_request.nutid_user_v1.profiles[this].to_dict() != db_user.profiles[this].to_dict():
                        self.context.logger.info(
                            f'Profile {this}/{update_request.nutid_user_v1.profiles[this]} updated'
                        )
                        nutid_changed = True
                    else:
                        self.context.logger.info(
                            f'Profile {this}/{update_request.nutid_user_v1.profiles[this]} not changed'
                        )
                for this in db_user.profiles.keys():
                    if this not in update_request.nutid_user_v1.profiles:
                        self.context.logger.info(f'Profile {this}/{db_user.profiles[this]} removed')
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
                # if self._comparable_linked_accounts(_db_linked_accounts) != self._comparable_linked_accounts(
                #    db_user.linked_accounts
                # ):
                if sorted(_db_linked_accounts, key=lambda x: x.value) != sorted(
                    db_user.linked_accounts, key=lambda x: x.value
                ):
                    db_user.linked_accounts = _db_linked_accounts
                    self.context.logger.info(f'Updated linked_accounts: {db_user.linked_accounts}')
                    nutid_changed = True

            self.context.logger.debug(f'Core changed: {core_changed}, nutid_changed: {nutid_changed}')
            if core_changed or nutid_changed:
                self._save_user(req, db_user)
                add_api_event(
                    context=self.context,
                    data_owner=req.context['data_owner'],
                    db_obj=db_user,
                    resource_type=SCIMResourceType.USER,
                    level=EventLevel.INFO,
                    status=EventStatus.UPDATED,
                    message='User was updated',
                )
            else:
                self.context.logger.info(f'No changes detected')

            self._db_user_to_response(req=req, resp=resp, db_user=db_user)
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")

    def on_post(self, req: Request, resp: Response):
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
                   "version":"W\/\"e180ee84f0671b1\""
                 },
                 "name":{
                   "formatted":"Ms. Barbara J Jensen III",
                   "familyName":"Jensen",
                   "givenName":"Barbara"
                 },
                 "userName":"bjensen"
               }
        """
        try:
            self.context.logger.info(f'Creating user')

            create_request: UserCreateRequest = UserCreateRequestSchema().load(req.media)
            self.context.logger.debug(create_request)

            if not self._acceptable_linked_accounts(create_request.nutid_user_v1.linked_accounts):
                raise BadRequest(detail='Invalid nutid linked_accounts')

            # convert from one type of profiles to another
            profiles = {}
            for profile_name, profile in create_request.nutid_user_v1.profiles.items():
                profiles[profile_name] = ScimApiProfile(attributes=profile.attributes, data=profile.data)

            # convert from one type of linked accounts to another
            linked_accounts = [
                ScimApiLinkedAccount(issuer=x.issuer, value=x.value, parameters=x.parameters)
                for x in create_request.nutid_user_v1.linked_accounts
            ]
            db_user = ScimApiUser(
                external_id=create_request.external_id,
                name=ScimApiName(**asdict(create_request.name)),
                emails=[ScimApiEmail(**asdict(email)) for email in create_request.emails],
                phone_numbers=[ScimApiPhoneNumber(**asdict(number)) for number in create_request.phone_numbers],
                preferred_language=create_request.preferred_language,
                profiles=profiles,
                linked_accounts=linked_accounts,
            )

            self._save_user(req, db_user)
            add_api_event(
                context=self.context,
                data_owner=req.context['data_owner'],
                db_obj=db_user,
                resource_type=SCIMResourceType.USER,
                level=EventLevel.INFO,
                status=EventStatus.CREATED,
                message='User was created',
            )

            self._db_user_to_response(req=req, resp=resp, db_user=db_user)
            resp.status = HTTP_201
        except ValidationError as e:
            raise BadRequest(detail=f"{e}")

    @staticmethod
    def _acceptable_linked_accounts(value: List[LinkedAccount]):
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


class UsersSearchResource(BaseResource):
    def on_post(self, req: Request, resp: Response):
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
        self.context.logger.info(f'Searching for users(s)')

        try:
            query: SearchRequest = SearchRequestSchema().load(req.media)
        except ValidationError as e:
            raise BadRequest(detail=f'{e}')

        self.context.logger.debug(f'Parsed user search query: {query}')

        filter = parse_search_filter(query.filter)

        if filter.attr == 'externalid':
            users = self._filter_externalid(req, filter)
            total_count = len(users)
        elif filter.attr == 'meta.lastmodified':
            # SCIM start_index 1 equals item 0
            users, total_count = self._filter_lastmodified(req, filter, skip=query.start_index - 1, limit=query.count)
        else:
            raise BadRequest(scim_type='invalidFilter', detail=f'Can\'t filter on attribute {filter.attr}')

        list_response = ListResponse(resources=self._users_to_resources_dicts(req, users), total_results=total_count)

        resp.media = ListResponseSchema().dump(list_response)

    @staticmethod
    def _users_to_resources_dicts(req: Request, users: Sequence[ScimApiUser]) -> List[Dict[str, Any]]:
        _attributes = req.media.get('attributes')
        # TODO: include the requested attributes, not just id
        return [{'id': str(user.scim_id)} for user in users]

    @staticmethod
    def _filter_externalid(req: Request, filter: SearchFilter) -> List[ScimApiUser]:
        if filter.op != 'eq':
            raise BadRequest(scim_type='invalidFilter', detail='Unsupported operator')
        if not isinstance(filter.val, str):
            raise BadRequest(scim_type='invalidFilter', detail='Invalid externalId')

        user = ctx_userdb(req).get_user_by_external_id(filter.val)

        if not user:
            return []

        return [user]

    @staticmethod
    def _filter_lastmodified(
        req: Request, filter: SearchFilter, skip: Optional[int] = None, limit: Optional[int] = None
    ) -> Tuple[List[ScimApiUser], int]:
        if filter.op not in ['gt', 'ge']:
            raise BadRequest(scim_type='invalidFilter', detail='Unsupported operator')
        if not isinstance(filter.val, str):
            raise BadRequest(scim_type='invalidFilter', detail='Invalid datetime')
        return ctx_userdb(req).get_users_by_last_modified(
            operator=filter.op, value=datetime.fromisoformat(filter.val), skip=skip, limit=limit
        )
