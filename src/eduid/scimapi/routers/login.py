import datetime

from fastapi import APIRouter, Response
from jwcrypto import jwt

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
    signing_key = req.app.context.jwks.get_key(req.app.context.config.signing_key_id)
    claims = {
        'kid': req.app.context.config.signing_key_id,
        'data_owner': token_req.data_owner,
        'exp': expire.timestamp(),
    }
    token = jwt.JWT(header={'alg': 'ES256'}, claims=claims)
    token.make_signed_token(signing_key)
    resp.headers['Authorization'] = f'Bearer {token.serialize()}'
