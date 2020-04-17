from falcon import Request, Response
from jose import jwt

from eduid_scimapi.exceptions import Unauthorized
from eduid_scimapi.resources.base import BaseResource


class LoginResource(BaseResource):
    def on_get(self, req: Request, resp: Response):
        self.context.logger.info(f'Logging in')
        data_owner = req.media['data_owner']
        if data_owner not in self.context._userdbs:
            raise Unauthorized()
        token = jwt.encode(
            {'data_owner': data_owner}, self.context.config.authorization_token_secret, algorithm='HS256'
        )
        resp.set_header('Authorization', f'Bearer {token}')
