import re

from fastapi import Request, Response
from jose import ExpiredSignatureError, jwt
from starlette.datastructures import URL
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import Message

from eduid.scimapi.context import Context
from eduid.scimapi.context_request import ContextRequestMixin
from eduid.scimapi.exceptions import Unauthorized


# middleware needs to return a reponse
# some background: https://github.com/tiangolo/fastapi/issues/458
def return_error_response(status_code: int, detail: str):
    return PlainTextResponse(status_code=status_code, content=detail)


# Hack to be able to get request body both now and later
# https://github.com/encode/starlette/issues/495#issuecomment-513138055
async def set_body(request: Request, body: bytes):
    async def receive() -> Message:
        return {'type': 'http.request', 'body': body}

    request._receive = receive


async def get_body(request: Request) -> bytes:
    body = await request.body()
    await set_body(request, body)
    return body


class BaseMiddleware(BaseHTTPMiddleware, ContextRequestMixin):
    def __init__(self, app, context: Context):
        super().__init__(app)
        self.context = context

    async def dispatch(self, req: Request, call_next) -> Response:
        return await call_next(req)


class ScimMiddleware(BaseMiddleware):
    async def dispatch(self, req: Request, call_next) -> Response:
        req = self.make_context_request(req)
        self.context.logger.debug(f'process_request: {req.method} {req.url.path}')
        # TODO: fix me? is this needed?
        # if req.method == 'POST':
        #     if req.path == '/login':
        #         if req.content_type != 'application/json':
        #             raise UnsupportedMediaTypeMalformed(
        #                 detail=f'{req.content_type} is an unsupported media type for {req.path}'
        #             )
        #     elif req.path == '/notifications':
        #         if req.content_type == 'text/plain; charset=UTF-8':
        #             # We know the body is json, set the correct content type
        #             req.content_type = 'application/json'
        #     elif req.content_type != 'application/scim+json':
        #         raise UnsupportedMediaTypeMalformed(detail=f'{req.content_type} is an unsupported media type')
        resp = await call_next(req)

        self.context.logger.debug(f'process_response: {req.method} {req.url.path}')
        # Default to 'application/json' if responding with an error message
        # if req_succeeded and resp.body:
        #     # candidates should be sorted by increasing desirability
        #     # preferred = request.client_prefers(('application/json', 'application/scim+json'))
        #
        #     preferred = None
        #     self.context.logger.debug(f'Client prefers content-type {preferred}')
        #     if preferred is None:
        #         preferred = 'application/scim+json'
        #         self.context.logger.debug(f'Default content-type {preferred} used')
        #     resp.headers.content_type = preferred
        return resp


class AuthenticationMiddleware(BaseMiddleware):
    def __init__(self, app, context: Context):
        super().__init__(app, context)
        self.no_authn_urls = self.context.config.no_authn_urls
        self.context.logger.debug('No auth allow urls: {}'.format(self.no_authn_urls))

    def _is_no_auth_path(self, url: URL) -> bool:
        for regex in self.no_authn_urls:
            m = re.match(regex, url.path)
            if m is not None:
                self.context.logger.debug('{} matched allow list'.format(url.path))
                return True
        return False

    async def dispatch(self, req: Request, call_next) -> Response:
        req = self.make_context_request(req)

        if self._is_no_auth_path(req.url):
            return await call_next(req)

        auth = req.headers.get('Authorization')

        if not req.app.context.config.authorization_mandatory and (not auth or not auth.startswith('Bearer ')):
            # Authorization is optional
            self.context.logger.info('No authorization header provided - proceeding anyway')
            req.context.data_owner = 'eduid.se'
            req.context.userdb = self.context.get_userdb(req.context.data_owner)
            req.context.groupdb = self.context.get_groupdb(req.context.data_owner)
            req.context.invitedb = self.context.get_invitedb(req.context.data_owner)
            req.context.eventdb = self.context.get_eventdb(req.context.data_owner)
            return await call_next(req)

        token = auth[len('Bearer ') :]
        try:
            claims = jwt.decode(token, self.context.config.authorization_token_secret, algorithms=['HS256'])
        except ExpiredSignatureError:
            self.context.logger.info(f'Bearer token expired')
            raise Unauthorized(detail='Signature expired')

        data_owner = claims.get('data_owner')
        if data_owner not in self.context.config.data_owners:
            self.context.logger.error(f'Data owner {repr(data_owner)} not configured')
            raise Unauthorized(detail='Unknown data_owner')

        req.context.data_owner = data_owner
        req.context.userdb = self.context.get_userdb(data_owner)
        req.context.groupdb = self.context.get_groupdb(data_owner)
        req.context.invitedb = self.context.get_invitedb(data_owner)
        req.context.eventdb = self.context.get_eventdb(data_owner)

        self.context.logger.debug(f'Bearer token data owner: {data_owner}')
        return await call_next(req)
