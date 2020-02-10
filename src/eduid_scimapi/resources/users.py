import uuid
from datetime import datetime
from typing import Optional

from falcon import Request, Response

from eduid_scimapi.base import BaseResource
from eduid_scimapi.exceptions import BadRequest
from eduid_scimapi.user import User


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

        user = User(username=username,  # TODO: should probably be eduid eppn?
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

