import json
import logging
import re
from copy import copy
from typing import Any, Mapping, Optional

from fastapi import Request, Response
from jwcrypto import jwt
from jwcrypto.common import JWException
from pydantic import BaseModel, Field, StrictInt, ValidationError, validator
from starlette.datastructures import URL
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import Message

from eduid.common.utils import removeprefix
from eduid.scimapi.config import DataOwnerName, ScimApiConfig, ScopeName
from eduid.scimapi.context import Context
from eduid.scimapi.context_request import ContextRequestMixin
from eduid.scimapi.exceptions import Unauthorized, http_error_detail_handler


class SudoAccess(BaseModel):
    type: str
    scope: ScopeName


class RequestedAccessDenied(Exception):
    """Break out of get_data_owner when requested access (in the token) is not allowed"""

    pass


class AuthnBearerToken(BaseModel):
    """
    Data we recognise from authentication bearer token JWT claims.
    """

    scim_config: ScimApiConfig  # must be listed first, used in validators
    version: StrictInt
    requested_access: list[SudoAccess] = Field(default=[])
    scopes: set[ScopeName] = Field(default=set())

    def __str__(self):
        return f"<{self.__class__.__name__}: scopes={self.scopes}, requested_access={self.requested_access}>"

    @validator("version")
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError("Unknown version")
        return v

    @validator("scopes")
    def validate_scopes(cls, v: set[ScopeName], values: Mapping[str, Any]) -> set[ScopeName]:
        config = values.get("scim_config")
        if not config:
            raise ValueError("Can't validate without scim_config")
        canonical_scopes = {config.scope_mapping.get(x, x) for x in v}
        return canonical_scopes

    @validator("requested_access")
    def validate_requested_access(cls, v: list[SudoAccess], values: Mapping[str, Any]) -> list[SudoAccess]:
        config = values.get("scim_config")
        if not config:
            raise ValueError("Can't validate without scim_config")
        new_access: list[SudoAccess] = []
        for this in v:
            if this.type != config.requested_access_type:
                # not meant for us
                continue
            this.scope = config.scope_mapping.get(this.scope, this.scope)
            new_access += [this]
        return new_access

    def get_data_owner(self, logger: logging.Logger) -> Optional[DataOwnerName]:
        """
        Get the data owner to use.

        Primarily, this is done by searching for a data owner matching one of the 'scopes' in the
        JWT (scopes are inserted into the JWT by the Sunet auth server).

        Some requesters might be allowed (in configuration) to 'sudo' to certain data owners too,
        by passing 'access' to the Sunet authn server, which will be found as 'requested_access' in the JWT.

        A requester with more than one scope and more than one data owner can use the same mechanism
        as used to 'sudo' in order to indicate which of their data owners they want to use now.

        Example straight forward minimal JWT:

          {'version': 1, 'scopes': 'example.org'}

        Example 'sudo':

          {'version': 1, 'scopes': 'sudoer.example.org', requested_access: {'type': 'scim-api', 'scope': 'example.edu'}}
        """

        allowed_scopes = self._get_allowed_scopes(self.scim_config, logger)
        logger.debug(f"Request {self}, allowed scopes: {allowed_scopes}")

        for this in self.requested_access:
            _allowed = this.scope in allowed_scopes
            _found = self.scim_config.data_owners.get(DataOwnerName(this.scope))
            logger.debug(f"Requested access to scope {this.scope}, allowed {_allowed}, found: {_found}")
            if not _allowed:
                _sorted = ", ".join(sorted(list(allowed_scopes)))
                raise RequestedAccessDenied(f"Requested access to scope {this.scope} not in allow-list: {_sorted}")
            if _allowed and _found:
                return DataOwnerName(this.scope)

        # sort to be deterministic
        for scope in sorted(list(self.scopes)):
            # checking allowed_scopes here might seem superfluous, but some client with multiple
            # scopes can request a specific one using the requested_access, and then only that one
            # scope is in allowed_scopes
            _allowed = scope in allowed_scopes
            _found = self.scim_config.data_owners.get(DataOwnerName(scope))
            logger.debug(f"Trying scope {scope}, allowed {_allowed}, found: {_found}")
            if _allowed and _found:
                return DataOwnerName(scope)

        return None

    def _get_allowed_scopes(self, config: ScimApiConfig, logger: logging.Logger) -> set[ScopeName]:
        """
        Make a set of all the allowed scopes for the requester.

        The allowed scopes are always the scopes the requester has (the scopes come from federation metadata,
        the Sunet authn server inserts them in the JWT), and possibly others as found in configuration.
        """
        _scopes = copy(self.scopes)
        for this in self.scopes:
            if this in config.scope_sudo:
                _sudo_scopes = config.scope_sudo[this]
                logger.debug(f"Request from scope {this}, allowing sudo to scopes {_sudo_scopes}")
                _scopes.update(_sudo_scopes)
        return _scopes


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

        if "scim_config" in claims:
            self.context.logger.warning(f"JWT has scim_config: {claims}")
            return await http_error_detail_handler(req=req, exc=Unauthorized(detail="Bearer token error"))

        try:
            self.context.logger.debug(f"Parsing claims: {claims}")
            token = AuthnBearerToken(scim_config=self.context.config, **claims)
            self.context.logger.debug(f"Bearer token: {token}")
        except ValidationError:
            self.context.logger.exception("Authorization Bearer Token error")
            return await http_error_detail_handler(req=req, exc=Unauthorized(detail="Bearer token error"))

        try:
            data_owner = token.get_data_owner(self.context.logger)
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

        return await call_next(req)
