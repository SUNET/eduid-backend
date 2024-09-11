import datetime

from fastapi import Response
from jwcrypto import jwt

from eduid.common.fastapi.context_request import ContextRequest
from eduid.common.models.bearer_token import AuthSource
from eduid.scimapi.api_router import APIRouter
from eduid.scimapi.exceptions import ErrorDetail, NotFound, Unauthorized
from eduid.scimapi.models.login import TokenRequest

login_router = APIRouter(
    prefix="/login",
    responses={
        400: {"description": "Bad request", "model": ErrorDetail},
        404: {"description": "Not found", "model": ErrorDetail},
        500: {"description": "Internal server error", "model": ErrorDetail},
    },
)


@login_router.post("")
async def get_token(req: ContextRequest, resp: Response, token_req: TokenRequest) -> None:
    if not req.app.config.login_enabled:
        raise NotFound()
    req.app.context.logger.info("Logging in")
    if token_req.data_owner not in req.app.context.config.data_owners:
        raise Unauthorized()
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    expire = now + datetime.timedelta(seconds=req.app.context.config.authorization_token_expire)
    signing_key = req.app.context.jwks.get_key(req.app.context.config.signing_key_id)
    claims = {
        "kid": req.app.context.config.signing_key_id,
        "exp": expire.timestamp(),
        "scopes": [token_req.data_owner],
        "version": 1,
        "auth_source": AuthSource.CONFIG,
    }
    token = jwt.JWT(header={"alg": "ES256"}, claims=claims)
    token.make_signed_token(signing_key)
    resp.headers["Authorization"] = f"Bearer {token.serialize()}"
