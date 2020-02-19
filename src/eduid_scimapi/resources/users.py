import uuid
import re
from datetime import datetime
from typing import Optional

from falcon import Request, Response

from eduid_scimapi.base import BaseResource
from eduid_scimapi.exceptions import BadRequest
from eduid_scimapi.scimuser import ScimUser
from eduid_userdb.user import User


class UsersResource(BaseResource):

    def on_get(self, req: Request, resp: Response, user_id):
        self.context.logger.info(f'Fetching user {user_id}')

        user = self.context.users.get_user_by_id(user_id)
        if not user:
            raise BadRequest(detail='User not found')

        location = self.url_for('Users', user.user_id)
        resp.set_header('Location', location)
        resp.set_header('ETag', user.etag)
        resp.media = user.to_dict(location)

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
        username = req.media.get('userName')
        if not username:
            raise BadRequest(detail='No userName in user creation request')

        if self.context.users.get_user_by_username(username):
            raise BadRequest(detail='User already exists')

        now = datetime.utcnow()

        user = ScimUser(username=username,  # TODO: should probably be eduid eppn?
                        external_id=username,
                        user_id=str(uuid.uuid4()),
                        name=req.media.get('name', {}),
                        version=1,
                        last_modified=now,
                        created=now,
                        )

        self.context.users.add_user(user)

        location = self.url_for('Users', user.user_id)
        resp.set_header('Location', location)
        resp.set_header('ETag', user.etag)
        resp.media = user.to_dict(location)


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

        user = None
        match = re.match('id eq "([a-z-]+)"', filter)
        if match:
            eppn = match.group(0)
            if eppn:
                user = self.context.userdb.get_user_by_eppn(eppn)

        assert isinstance(user, User)

        now = datetime.utcnow()

        user = ScimUser(username=user.eppn,
                        external_id='external_id',
                        user_id=user.eppn,
                        name={'displayName': user.display_name,
                              },
                        version=1,
                        last_modified=now,
                        created=now,
                        )

        self.context.users.add_user(user)

        location = self.url_for('Users', user.user_id)
        resp.set_header('Location', location)
        resp.set_header('ETag', user.etag)
        resp.media = user.to_dict(location)

