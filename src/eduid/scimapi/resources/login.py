import datetime

from falcon import Request, Response
from jose import jwt

from eduid.scimapi.exceptions import Unauthorized
from eduid.scimapi.resources.base import BaseResource


class LoginResource(BaseResource):
    def on_post(self, req: Request, resp: Response):
        self.context.logger.info(f'Logging in')
        data_owner = req.media['data_owner']
        if data_owner not in self.context.config.data_owners:
            raise Unauthorized()
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        expire = now + datetime.timedelta(seconds=self.context.config.authorization_token_expire)
        claims = {
            'data_owner': data_owner,
            'exp': expire,
        }
        token = jwt.encode(claims, self.context.config.authorization_token_secret, algorithm='HS256')
        resp.set_header('Authorization', f'Bearer {token}')
