import re
from typing import Any, Dict, Mapping, Optional

from falcon import Request, Response

from eduid_userdb.user import User

from eduid_scimapi.context import Context
from eduid_scimapi.exceptions import BadRequest
from eduid_scimapi.profile import Profile
from eduid_scimapi.resources.base import BaseResource
from eduid_scimapi.scimbase import SCIMSchema
from eduid_scimapi.user import ScimApiUser


class UsersResource(BaseResource):
    def on_get(self, req: Request, resp: Response, scim_id):
        self.context.logger.info(f'Fetching user {scim_id}')

        user = req.context['userdb'].get_user_by_scim_id(scim_id)
        if not user:
            raise BadRequest(detail='User not found')

        _add_eduid_PoC_profile(user, self.context)

        location = self.url_for('Users', user.scim_id)
        resp.set_header('Location', location)
        resp.set_header('ETag', user.etag)
        resp.media = user.to_scim_dict(location, data_owner=req.context['data_owner'])

    def on_put(self, req: Request, resp: Response, scim_id):
        self.context.logger.info(f'Fetching user {scim_id}')

        user = req.context['userdb'].get_user_by_scim_id(scim_id)
        if not user:
            raise BadRequest(detail='User not found')

        # TODO: check that meta.version in the request matches the user object loaded from the database

        self.context.logger.debug(f'Extra debug: user {scim_id} as dict:\n{user.to_dict()}')

        if SCIMSchema.NUTID_V1.value in req.media:
            if not user.external_id:
                self.context.logger.warning(f'User {user} has no external id, skipping NUTID update')
            parsed_profiles = _parse_nutid_profiles(req.media[SCIMSchema.NUTID_V1.value])

            # Look for changes
            changed = False
            for this in parsed_profiles.keys():
                if this not in user.profiles:
                    self.context.logger.info(f'Adding profile {this}/{parsed_profiles[this]} to user')
                    changed = True
                if parsed_profiles[this] != user.profiles[this]:
                    self.context.logger.info(f'Profile {this}/{parsed_profiles[this]} updated')
                    changed = True
                else:
                    self.context.logger.info(f'Profile {this}/{parsed_profiles[this]} not changed')
            for this in user.profiles.keys():
                if this not in parsed_profiles:
                    self.context.logger.info(f'Profile {this}/{parsed_profiles[this]} removed')
                    changed = True

            if changed:
                user.profiles = parsed_profiles
                req.context['userdb'].save(user)

        location = self.url_for('Users', user.scim_id)
        resp.set_header('Location', location)
        resp.set_header('ETag', user.etag)
        resp.media = user.to_scim_dict(location)

    def on_post(self, req: Request, resp: Response, user_id: Optional[str] = None):
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
        self.context.logger.info(f'Creating user {user_id}')

        if not req.media:
            raise BadRequest(detail='No data in user creation request')
        external_id = req.media.get('externalId')
        if not external_id:
            raise BadRequest(detail='No externalId in user creation request')

        profiles = _parse_nutid_profiles(req.media[SCIMSchema.NUTID_V1.value])
        user = ScimApiUser(external_id=external_id, profiles=profiles)
        req.context['userdb'].save(user)

        location = self.url_for('Users', user.scim_id)
        resp.set_header('Location', location)
        resp.set_header('ETag', user.etag)
        resp.media = user.to_scim_dict(location, debug=self.context.config.debug, data_owner=req.context['data_owner'])


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
             "encryptionKey": "h026jGKrSW%2BTTekkA8Y8mv8%2FGqkGgAfLzaj3ucD3STQ"
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
        self.context.logger.info(f'Searching for user(s)')

        if not req.media:
            raise BadRequest(detail='No data in user search request')
        # TODO: validate schemas, attributes etc.
        filter = req.media.get('filter')
        if not filter:
            raise BadRequest(detail='No filter in user search request')

        match = re.match('externalId eq "(.+?)"', filter)
        if not match:
            raise BadRequest(detail='Unrecognised filter')

        external_id = match.group(1)
        user = req.context['userdb'].get_user_by_external_id(external_id)

        if not user:
            # persist the scim_id for the search result by saving it as a ScimApiUser
            user = ScimApiUser(external_id=external_id)
            req.context['userdb'].save(user)

        _add_eduid_PoC_profile(user, self.context)

        if not user:
            # TODO: probably not the right way to signal this
            raise BadRequest(detail='User not found')

        location = self.url_for('Users', user.scim_id)
        resp.set_header('Location', location)
        resp.set_header('ETag', user.etag)
        resp.media = user.to_scim_dict(location, debug=self.context.config.debug, data_owner=req.context['data_owner'])


def _add_eduid_PoC_profile(user: ScimApiUser, context: Context) -> None:
    """ PoC: Dynamically add an 'eduid.se' or 'dev.eduid.se' profile with data from eduid """
    if user.external_id is None:
        return
    if user.external_id.endswith('@eduid.se') or user.external_id.endswith('@dev.eduid.se'):
        eppn, domain = user.external_id.split('@')
        context.logger.debug(f'Searching for eduid user with eppn {repr(eppn)}')

        eduid_user = context.eduid_userdb.get_user_by_eppn(eppn)
        assert isinstance(eduid_user, User)

        eduid_profile = Profile(attributes={'displayName': eduid_user.display_name,})
        user.profiles[domain] = eduid_profile


def _parse_nutid_profiles(data: Mapping[str, Any]) -> Dict[str, Profile]:
    res: Dict[str, Profile] = {key: Profile.from_dict(values) for key, values in data.items()}
    return res
