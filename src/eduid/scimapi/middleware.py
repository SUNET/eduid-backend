import json
import logging
import re
from copy import copy
from typing import List, Optional, Set

from fastapi import Request, Response
from jwcrypto import jwt
from jwcrypto.common import JWException
from pydantic import BaseModel, Field, StrictInt, constr, validator
from starlette.datastructures import URL
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import Message

from eduid.common.utils import removeprefix
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.context_request import ContextRequestMixin


class SudoAccess(BaseModel):
    type: str
    scope: Optional[constr(to_lower=True, min_length=4)] = None


class AuthnBearerToken(BaseModel):
    """
    Data we recognise from authentication bearer token JWT claims.
    """

    version: StrictInt
    requested_access: List[SudoAccess] = Field(default=[])
    scopes: Set[constr(to_lower=True, min_length=4)] = Field(default=[])

    @validator('version')
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError('Unknown version')
        return v

    def _requested_access_scopes(self, config: ScimApiConfig) -> List[str]:
        """ Filter out the access parts meant for this API.

        Can't (easily) be done in a validator since it depends on configuration.
        """
        # sort to be deterministic
        return sorted([x.scope for x in self.requested_access if x.scope and x.type == config.requested_access_type])

    def _get_allowed_scopes(self, config: ScimApiConfig, logger: logging.Logger) -> Set[str]:
        _scopes = copy(self.scopes)
        for this in self.scopes:
            if this in config.scope_sudo:
                _sudo_scopes = config.scope_sudo[this]
                logger.debug(f'Request from scope {this}, allowing sudo to scopes {_sudo_scopes}')
                _scopes.update(_sudo_scopes)
        return _scopes

    def _get_canonical_scope(self, scope: str, config: ScimApiConfig) -> str:
        if scope in config.scope_mapping:
            return config.scope_mapping[scope]
        return scope

    def get_data_owner(self, config: ScimApiConfig, logger: logging.Logger) -> Optional[str]:
        """ Given a configuration, deduce the data_owner to use. """
        allowed_scopes = self._get_allowed_scopes(config, logger)
        logger.debug(f'Request {self}, allowed scopes: {allowed_scopes}')

        for this in self._requested_access_scopes(config):
            _scope = self._get_canonical_scope(this, config)
            _allowed = _scope in allowed_scopes
            _found = config.data_owners.get(_scope)
            logger.debug(f'Requested access to scope {_scope}, allowed {_allowed}, found: {_found}')
            if _allowed and _found:
                return _scope

        # sort to be deterministic
        for this in sorted(list(self.scopes)):
            _scope = self._get_canonical_scope(this, config)
            # checking allowed_scopes here might seem superfluous, but some client with multiple
            # scopes can request a specific one using the requested_access, and then only that one
            # scope is in allowed_scopes
            _allowed = _scope in allowed_scopes
            _found = config.data_owners.get(_scope)
            logger.debug(f'Trying scope {_scope}, allowed {_allowed}, found: {_found}')
            if _allowed and _found:
                return _scope

        return None


# middleware needs to return a response
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
        path = url.path
        # Remove application root from path matching
        path = removeprefix(path, self.context.config.application_root)
        for regex in self.no_authn_urls:
            m = re.match(regex, path)
            if m is not None:
                self.context.logger.debug('{} matched allow list'.format(path))
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

        if not auth:
            return return_error_response(status_code=401, detail='No authentication header found')

        token = auth[len('Bearer ') :]
        _jwt = jwt.JWT()
        try:
            _jwt.deserialize(token, req.app.context.jwks)
            claims = json.loads(_jwt.claims)
        except (JWException, KeyError) as e:
            self.context.logger.info(f'Bearer token error: {e}')
            return return_error_response(status_code=401, detail='Bearer token error')

        token = AuthnBearerToken(**claims)
        self.context.logger.debug(f'Bearer token: {token}')

        data_owner = token.get_data_owner(self.context.config, self.context.logger)
        self.context.logger.debug(f'Bearer token data owner: {data_owner}')

        if not data_owner or data_owner not in self.context.config.data_owners:
            self.context.logger.error(f'Data owner {repr(data_owner)} not configured')
            return return_error_response(status_code=401, detail='Unknown data_owner')

        req.context.data_owner = data_owner
        req.context.userdb = self.context.get_userdb(data_owner)
        req.context.groupdb = self.context.get_groupdb(data_owner)
        req.context.invitedb = self.context.get_invitedb(data_owner)
        req.context.eventdb = self.context.get_eventdb(data_owner)

        return await call_next(req)
