import re
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from eduid.maccapi.context import Context
from eduid.maccapi.context_request import ContextRequestMixin
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from jwcrypto import jwt
from jwcrypto.common import JWException
import json

def return_error_response(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={'detail': detail},
    )

class AuthenticationMiddleware(BaseHTTPMiddleware, ContextRequestMixin):
    def __init__(self, app, context: Context):
        super().__init__(app)
        self.context = context
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request = self.make_context_request(request)

        path = request.url.path.lstrip(request.app.config.application_root)
        method_path = f"{request.method.lower()}:{path}"

        if not path:
            return return_error_response(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid path")

        if self._is_no_auth_path(request, path):
            return await call_next(request)
        
        auth = request.headers.get("Authorization")

        if not request.app.context.config.authorization_mandatory and (not auth or not auth.startswith("Bearer ")):
            self.context.logger.info("Authorization header not mandatory, skipping authorization check")
            return await call_next(request)

        if not auth:
            return return_error_response(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header")
        
        _token = auth[len("Bearer "):]
        self.context.logger.info(f"Bearer token: {_token}")
        _jwt = jwt.JWT()
        try:
            _jwt.deserialize(_token, request.app.context.jwks)
            claims = json.loads(_jwt.claims)
        except (JWException, KeyError, ValueError) as e:
            self.context.logger.info(f"Bearer token error: {e}")
            return return_error_response(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Bearer token")
        
        self.context.logger.info(f"Bearer token claims: {claims}")

        return await call_next(request)
    
    @staticmethod
    def _is_no_auth_path(request: Request, path: str) -> bool:
        for regex in request.app.config.no_authn_urls:
            m = re.match(regex, path)
            if m is not None:
                request.app.context.logger.debug(f"{path} matched allow list")
                return True
        return False
    