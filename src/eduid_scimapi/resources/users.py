import re
from typing import Optional

from falcon import Request, Response

from eduid_userdb.user import User

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
            changed = False
            data = req.media[SCIMSchema.NUTID_V1.value]
            if 'profiles' in data:
                for profile in data['profiles'].keys():
                    profile_data = data['profiles'][profile]
                    if profile in ['eduid.se', 'dev.eduid.se']:
                        self.context.logger.info(f'Special-processing profile "{profile}"')
                        if 'displayName' not in profile_data:
                            self.context.logger.info(f'No displayName in profile: {profile_data}')
                            continue

                        _old = user.profiles[profile].data.get('displayName')
                        _new = profile_data['displayName']
                        if _old != _new:
                            changed = True
                            self.context.logger.info(
                                f'Updating user {user.external_id} eduid display name from '
                                f'{repr(_old)} to {repr(_new)}'
                            )
                            user.profiles[profile].data['display_name'] = _new
                            # As a PoC, update the eduid userdb with this display name
                            eduid_user = self.context.eduid_userdb.get_user_by_eppn(user.profiles[profile].external_id)
                            assert eduid_user is not None
                            eduid_user.display_name = _new
                            self.context.eduid_userdb.save(eduid_user)
                    assert user.external_id  # please mypy
                    if profile not in user.profiles:
                        user.profiles[profile] = Profile(user.external_id, profile_data)
                    if user.profiles[profile].data != profile_data:
                        self.context.logger.info(
                            f'Updating user {user.external_id} profile {profile} with data:\n' f'{profile_data}'
                        )
                        user.profiles[profile].data = profile_data
                        changed = True
                    else:
                        self.context.logger.info(f'User {user.external_id} profile {profile} not changed')

            if changed:
                self.context.userdb.save(user)

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

        # TODO: parse NUTID profiles
        profiles = {}
        user = ScimApiUser(external_id=external_id, profiles=profiles)
        self.context.userdb.save(user)

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

        if external_id.endswith('@eduid.se') or external_id.endswith('@dev.eduid.se'):
            eppn = external_id.split('@')[0]  # remove domain part
            self.context.logger.debug(f'Searching for eduid user with eppn {repr(eppn)}')

            eduid_user = self.context.eduid_userdb.get_user_by_eppn(eppn)
            assert isinstance(eduid_user, User)

            eduid_profile = Profile(attributes={'displayName': eduid_user.display_name,})

            if not user:
                # persist the scim_id for the search result by saving it as a ScimApiUser
                user = ScimApiUser(external_id=external_id, profiles={'student': eduid_profile},)
                req.context['userdb'].save(user)

        if not user:
            # TODO: probably not the right way to signal this
            raise BadRequest(detail='User not found')

        location = self.url_for('Users', user.scim_id)
        resp.set_header('Location', location)
        resp.set_header('ETag', user.etag)
        resp.media = user.to_scim_dict(location, debug=self.context.config.debug, data_owner=req.context['data_owner'])
