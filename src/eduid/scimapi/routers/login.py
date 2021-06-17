import datetime

from fastapi import APIRouter, Response
from jose import jwt

from eduid.scimapi.context_request import ContextRequest
from eduid.scimapi.exceptions import Unauthorized
from eduid.scimapi.models.login import TokenRequest

login_router = APIRouter(prefix='/login')


@login_router.post('/')
async def get_token(req: ContextRequest, resp: Response, token_req: TokenRequest) -> None:
    req.app.context.logger.info(f'Logging in')
    if token_req.data_owner not in req.app.context.config.data_owners:
        raise Unauthorized()
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    expire = now + datetime.timedelta(seconds=req.app.context.config.authorization_token_expire)
    claims = {
        'data_owner': token_req.data_owner,
        'exp': expire,
    }
    token = jwt.encode(claims, req.app.context.config.authorization_token_secret, algorithm='HS256')
    resp.headers['Authorization'] = f'Bearer {token}'
