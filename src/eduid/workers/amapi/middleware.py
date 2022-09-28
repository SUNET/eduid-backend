import json
import re

from fastapi import Request, Response
from jwcrypto import jwt
from jwcrypto.common import JWException
from marshmallow import ValidationError
from pydantic import BaseModel, StrictInt, validator
from starlette.datastructures import URL
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import Message

from eduid.common.utils import removeprefix
from eduid.workers.amapi.context_request import ContextRequestMixin


class AccessDenied(Exception):
    """Break out of get_data_owner when requested access (in the token) is not allowed"""

    pass


class AuthnBearerToken(BaseModel):
    """
    Data we recognize from authentication bearer token JWT claims.
    """

    version: StrictInt
    requested_access: str
    app_name: str

    def __str__(self):
        return f"<{self.__class__.__name__}: scopes={self.scopes}, requested_access={self.requested_access}>"

    @validator("version")
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError("Unknown version")
        return v

    @validator("app_name")
    def validate_scopes(cls, v: str) -> str:
        if v != "amapi":
            raise ValueError("Unknown app_name")
        return v

    @validator("requested_access")
    def validate_requested_access(cls, v: str) -> str:
        if v != "amapi":
            raise ValueError("Unknown requested access")
        return v


# middleware needs to return a response
# some background: https://github.com/tiangolo/fastapi/issues/458
def return_error_response(status_code: int, detail: str):
    return PlainTextResponse(status_code=status_code, content=detail)


# Hack to be able to get request body both now and later
# https://github.com/encode/starlette/issues/495#issuecomment-513138055
async def set_body(request: Request, body: bytes):
    async def receive() -> Message:
        return {"type": "http.request", "body": body}

    request._receive = receive


async def get_body(request: Request) -> bytes:
    body = await request.body()
    await set_body(request, body)
    return body


class BaseMiddleware(BaseHTTPMiddleware, ContextRequestMixin):
    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, req: Request, call_next) -> Response:
        return await call_next(req)


class AuthenticationMiddleware(BaseMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.no_authn_urls = app.config.no_authn_urls
        app.logger.debug("No auth allow urls: {}".format(self.no_authn_urls))

    def _is_no_auth_path(self, url: URL) -> bool:
        path = url.path
        # Remove application root from path matching
        path = removeprefix(path, self.app.config.application_root)
        for regex in self.no_authn_urls:
            m = re.match(regex, path)
            if m is not None:
                self.app.logger.debug("{} matched allow list".format(path))
                return True
        return False

    async def dispatch(self, req: Request, call_next) -> Response:
        req = self.make_context_request(req)

        if self._is_no_auth_path(req.url):
            return await call_next(req)

        auth = req.headers.get("Authorization")

        if not auth:
            return return_error_response(status_code=401, detail="No authentication header found")

        token = auth[len("Bearer ") :]
        _jwt = jwt.JWT()
        try:
            _jwt.deserialize(token, req.app.jwks)
            claims = json.loads(_jwt.claims)
        except (JWException, KeyError, ValueError) as e:
            self.app.logger.info(f"Bearer token error: {e}")
            return return_error_response(status_code=401, detail="Bearer token error")

        try:
            token = AuthnBearerToken(**claims)
            self.app.logger.debug(f"Bearer token: {token}")
        except ValidationError:
            self.app.logger.exception("Authorization Bearer Token error")
            return return_error_response(status_code=401, detail="Bearer token error")

        try:
            # check if jwt user is allowed, return list of allowed endpoints
            token.app_name
            pass
        except AccessDenied as exc:
            self.app.logger.error(f"Access denied: {exc}")
            return return_error_response(status_code=401, detail="Data owner requested in access token denied")

        self.app.logger.info(f"Bearer token {token}")

        return await call_next(req)
