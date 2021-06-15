from __future__ import annotations

import logging
import traceback
import uuid
from typing import Dict, List, Optional, Union

from fastapi import HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from eduid.scimapi.models.scimbase import SCIMSchema

logger = logging.getLogger(__name__)


class ErrorDetail(BaseModel):
    scimType: Optional[str] = None
    schemas: List[str] = [SCIMSchema.ERROR.value]
    detail: Optional[Union[str, Dict, List]] = None
    status: Optional[int] = None


class SCIMErrorResponse(JSONResponse):
    media_type = "application/scim+json"


async def unexpected_error_handler(req: Request, ex: StarletteHTTPException):
    error_id = uuid.uuid4()
    logger.error(f'Unexpected error {error_id}: {ex}')
    logger.error(traceback.format_exc())
    ex.detail = f'Please reference the error id {error_id} when reporting this issue'
    return await http_exception_handler(req, ex)


async def validation_exception_handler(req: Request, ex: RequestValidationError):
    resp = SCIMErrorResponse()
    resp.status_code = 400
    detail = ErrorDetail(
        schemas=[SCIMSchema.ERROR.value], scimType='invalidSyntax', detail=ex.errors(), status=resp.status_code
    )
    resp.body = detail.json(exclude_none=True).encode('utf-8')
    return resp


async def http_error_detail_handler(req: Request, ex: HTTPErrorDetail):
    resp = SCIMErrorResponse()
    resp.status_code = ex.status_code
    resp.body = ex.error_detail.json(exclude_none=True).encode('utf-8')
    if ex.extra_headers:
        resp.headers.update(ex.extra_headers)
    return resp


class HTTPErrorDetail(HTTPException):
    def __init__(
        self,
        status_code: int,
        detail: str = None,
        schemas: Optional[List[str]] = None,
        scim_type: Optional[str] = None,
    ):
        if schemas is None:
            schemas = [SCIMSchema.ERROR.value]

        super().__init__(status_code=status_code, detail=detail)
        self._error_detail = ErrorDetail(scimType=scim_type, schemas=schemas, detail=detail, status=self.status_code)
        self._extra_headers: Optional[Dict] = None

    @property
    def error_detail(self) -> ErrorDetail:
        return self._error_detail

    @property
    def extra_headers(self) -> Dict:
        return self._extra_headers

    @extra_headers.setter
    def extra_headers(self, headers: Dict):
        self._extra_headers = headers


class BadRequest(HTTPErrorDetail):
    def __init__(self, **kwargs):
        super().__init__(status_code=400, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = 'Bad Request'


class Unauthorized(HTTPErrorDetail):
    def __init__(self, **kwargs):
        super().__init__(status_code=401, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = 'Unauthorized request'


class NotFound(HTTPErrorDetail):
    def __init__(self, **kwargs):
        super().__init__(status_code=404, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = 'Resource not found'


class UnsupportedMediaTypeMalformed(HTTPErrorDetail):
    def __init__(self, **kwargs):
        super().__init__(status_code=422, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = 'Request was made with an unsupported media type'


class MethodNotAllowedMalformed(HTTPErrorDetail):
    def __init__(self, **kwargs):
        super().__init__(status_code=405, **kwargs)
        if not self.error_detail.detail:
            allowed_methods = kwargs.get('allowed_methods')
            self.error_detail.detail = f'The used HTTP method is not allowed. Allowed methods: {allowed_methods}'


class ServerInternal(HTTPErrorDetail):
    def __init__(self, **kwargs):
        super().__init__(status_code=500, **kwargs)
