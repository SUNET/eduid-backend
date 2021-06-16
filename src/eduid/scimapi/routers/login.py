import datetime

from fastapi import APIRouter, Response
from jose import jwt

from eduid.scimapi.exceptions import Unauthorized
from eduid.scimapi.models.login import TokenRequest

login_router = APIRouter(prefix='/login')


@login_router.post('/')
async def get_token(self, token_req: TokenRequest, response: Response) -> None:
    self.context.logger.info(f'Logging in')
    if token_req.data_owner not in self.context.config.data_owners:
        raise Unauthorized()
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    expire = now + datetime.timedelta(seconds=self.context.config.authorization_token_expire)
    claims = {
        'data_owner': token_req.data_owner,
        'exp': expire,
    }
    token = jwt.encode(claims, self.context.config.authorization_token_secret, algorithm='HS256')
    response.headers['Authorization'] = f'Bearer {token}'
