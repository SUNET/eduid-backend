import json
import re

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from jwcrypto import jwt
from jwcrypto.common import JWException
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

from eduid.common.fastapi.context_request import ContextRequestMixin
from eduid.common.models.bearer_token import AuthnBearerToken, RequestedAccessDenied
from eduid.maccapi.context import Context
from eduid.maccapi.context_request import MaccAPIContext


def return_error_response(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
    )


class AuthenticationMiddleware(BaseHTTPMiddleware, ContextRequestMixin):
    def __init__(self, app: ASGIApp, context: Context) -> None:
        super().__init__(app)
        self.context = context

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request = self.make_context_request(request, context_class=MaccAPIContext)

        path = request.url.path.removeprefix(request.app.config.application_root)

        if not path:
            return return_error_response(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid path")

        if self._is_no_auth_path(request, path):
            return await call_next(request)

        auth = request.headers.get("Authorization")

        if not request.app.context.config.authorization_mandatory and (not auth or not auth.startswith("Bearer ")):
            self.context.logger.info("Authorization header not mandatory, skipping authorization check")
            return await call_next(request)

        if not auth:
            return return_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header"
            )

        _token = auth[len("Bearer ") :]
        self.context.logger.info(f"Bearer token: {_token}")
        _jwt = jwt.JWT()
        try:
            _jwt.deserialize(_token, request.app.context.jwks)
            claims = json.loads(_jwt.claims)
        except (JWException, KeyError, ValueError) as e:
            self.context.logger.info(f"Bearer token error: {e}")
            return return_error_response(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Bearer token")

        if "config" in claims:
            self.context.logger.warning(f"JWT has config: {claims}")
            return return_error_response(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Bearer token")

        try:
            self.context.logger.debug(f"Parsing claims: {claims}")
            token = AuthnBearerToken(config=self.context.config, **claims)
            self.context.logger.debug(f"Bearer token: {token}")
        except ValidationError:
            self.context.logger.exception("Authorization Bearer Token error")
            return return_error_response(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Bearer token")

        try:
            token.validate_auth_source()
        except RequestedAccessDenied as e:
            self.context.logger.error(f"Access denied: {e}")
            return return_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication source or assurance level invalid"
            )

        try:
            data_owner = token.get_data_owner()
        except RequestedAccessDenied as e:
            self.context.logger.error(f"Access denied: {e}")
            return return_error_response(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Data owner requested in access token denied"
            )

        if not data_owner or data_owner not in self.context.config.data_owners:
            self.context.logger.error(f"Data owner {repr(data_owner)} not configured")
            return return_error_response(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown data_owner")

        assert isinstance(request.context, MaccAPIContext)  # please mypy
        request.context.data_owner = data_owner
        request.context.manager_eppn = token.saml_eppn

        return await call_next(request)

    @staticmethod
    def _is_no_auth_path(request: Request, path: str) -> bool:
        for regex in request.app.config.no_authn_urls:
            m = re.match(regex, path)
            if m is not None:
                request.app.context.logger.debug(f"{path} matched allow list")
                return True
        return False
