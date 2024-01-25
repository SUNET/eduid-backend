import json
import logging
import re
from copy import copy
from typing import Any, Mapping, Optional

from fastapi import Request, Response
from jwcrypto import jwt
from jwcrypto.common import JWException
from pydantic import BaseModel, Field, ValidationError, root_validator, validator
from starlette.datastructures import URL
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import Message

from eduid.common.config.base import DataOwnerName, ScopeName
from eduid.common.models.bearer_token import (
    AuthenticationError,
    AuthnBearerToken,
    AuthorizationError,
    AuthSource,
    RequestedAccessDenied,
    SudoAccess,
)
from eduid.common.utils import removeprefix
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.context_request import ContextRequestMixin
from eduid.scimapi.exceptions import Unauthorized, http_error_detail_handler
from eduid.userdb.scimapi import ScimApiGroupDB

logger = logging.getLogger(__name__)


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
    def __init__(self, app, context: Context):
        super().__init__(app)
        self.context = context

    async def dispatch(self, req: Request, call_next) -> Response:
        return await call_next(req)


class ScimMiddleware(BaseMiddleware):
    async def dispatch(self, req: Request, call_next) -> Response:
        req = self.make_context_request(req)
        self.context.logger.debug(f"process_request: {req.method} {req.url.path}")
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

        self.context.logger.debug(f"process_response: {req.method} {req.url.path}")
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
        self.context.logger.debug(f"No auth allow urls: {self.no_authn_urls}")

    def _is_no_auth_path(self, url: URL) -> bool:
        path = url.path
        # Remove application root from path matching
        path = removeprefix(path, self.context.config.application_root)
        for regex in self.no_authn_urls:
            m = re.match(regex, path)
            if m is not None:
                self.context.logger.debug(f"{path} matched allow list")
                return True
        return False

    async def dispatch(self, req: Request, call_next) -> Response:
        req = self.make_context_request(req)

        if self._is_no_auth_path(req.url):
            return await call_next(req)

        auth = req.headers.get("Authorization")

        if not req.app.context.config.authorization_mandatory and (not auth or not auth.startswith("Bearer ")):
            # Authorization is optional
            self.context.logger.info("No authorization header provided - proceeding anyway")
            req.context.data_owner = DataOwnerName("eduid.se")
            req.context.userdb = self.context.get_userdb(req.context.data_owner)
            req.context.groupdb = self.context.get_groupdb(req.context.data_owner)
            req.context.invitedb = self.context.get_invitedb(req.context.data_owner)
            req.context.eventdb = self.context.get_eventdb(req.context.data_owner)
            return await call_next(req)

        if not auth:
            return await http_error_detail_handler(req=req, exc=Unauthorized(detail="No authentication header found"))

        _token = auth[len("Bearer ") :]
        _jwt = jwt.JWT()
        try:
            _jwt.deserialize(_token, req.app.context.jwks)
            claims = json.loads(_jwt.claims)
        except (JWException, KeyError, ValueError) as e:
            self.context.logger.info(f"Bearer token error: {e}")
            return await http_error_detail_handler(req=req, exc=Unauthorized(detail="Bearer token error"))

        if "config" in claims:
            self.context.logger.warning(f"JWT has config: {claims}")
            return await http_error_detail_handler(req=req, exc=Unauthorized(detail="Bearer token error"))

        try:
            self.context.logger.debug(f"Parsing claims: {claims}")
            token = AuthnBearerToken(config=self.context.config, **claims)
            self.context.logger.debug(f"Bearer token: {token}")
        except ValidationError:
            self.context.logger.exception("Authorization Bearer Token error")
            return await http_error_detail_handler(req=req, exc=Unauthorized(detail="Bearer token error"))

        try:
            token.validate_auth_source()
        except AuthenticationError as exc:
            self.context.logger.error(f"Access denied: {exc}")
            return await http_error_detail_handler(
                req=req, exc=Unauthorized(detail="Authentication source or assurance level invalid")
            )

        try:
            data_owner = token.get_data_owner()
        except RequestedAccessDenied as exc:
            self.context.logger.error(f"Access denied: {exc}")
            return await http_error_detail_handler(
                req=req, exc=Unauthorized(detail="Data owner requested in access token denied")
            )
        self.context.logger.info(f"Bearer token {token}, data owner: {data_owner}")

        if not data_owner or data_owner not in self.context.config.data_owners:
            self.context.logger.error(f"Data owner {repr(data_owner)} not configured")
            return await http_error_detail_handler(req=req, exc=Unauthorized(detail="Unknown data_owner"))

        req.context.data_owner = data_owner
        req.context.userdb = self.context.get_userdb(data_owner)
        req.context.groupdb = self.context.get_groupdb(data_owner)
        req.context.invitedb = self.context.get_invitedb(data_owner)
        req.context.eventdb = self.context.get_eventdb(data_owner)

        # check authorization for interaction authentications
        try:
            if token.auth_source == AuthSource.INTERACTION:
                token.validate_saml_entitlements(data_owner=data_owner, groupdb=req.context.groupdb)
        except AuthorizationError as exc:
            self.context.logger.error(f"Access denied: {exc}")
            return await http_error_detail_handler(
                req=req, exc=Unauthorized(detail="Missing correct entitlement in saml data")
            )

        return await call_next(req)
