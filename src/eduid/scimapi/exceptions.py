from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response

from eduid.common.models.scim_base import SCIMSchema

logger = logging.getLogger(__name__)


class MaxRetriesReached(Exception):
    pass


class ErrorDetail(BaseModel):
    scimType: str | None = None
    schemas: list[str] = [SCIMSchema.ERROR.value]
    detail: str | dict | list | None = None
    status: int | None = None


class SCIMErrorResponse(JSONResponse):
    media_type = "application/scim+json"


async def unexpected_error_handler(req: Request, exc: Exception) -> Response:
    error_id = uuid.uuid4()
    logger.error(f"unexpected error {error_id}: {req.method} {req.url.path} - {exc}")
    http_exception = StarletteHTTPException(
        status_code=500, detail=f"Please reference the error id {error_id} when reporting this issue"
    )
    return await http_exception_handler(req, http_exception)


async def validation_exception_handler(req: Request, exc: RequestValidationError) -> SCIMErrorResponse:
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    detail = ErrorDetail(
        schemas=[SCIMSchema.ERROR.value],
        scimType="invalidSyntax",
        detail=jsonable_encoder(list(exc.errors())),
        status=status_code,
    )
    logger.error(f"validation exception: {req.method} {req.url.path} - {exc} - {detail}")
    return SCIMErrorResponse(content=detail.dict(exclude_none=True), status_code=status_code)


async def http_error_detail_handler(req: Request, exc: HTTPErrorDetail) -> SCIMErrorResponse:
    logger.error(f"error detail: {req.method} {req.url.path} - {exc} - {exc.error_detail}")
    return SCIMErrorResponse(
        content=exc.error_detail.dict(exclude_none=True),
        headers=exc.extra_headers,
        # default to status code 400 as error_detail status should be optional
        status_code=exc.error_detail.status or 400,
    )


class HTTPErrorDetail(Exception):
    def __init__(
        self,
        status_code: int,
        detail: str | None = None,
        schemas: list[str] | None = None,
        scim_type: str | None = None,
    ) -> None:
        if schemas is None:
            schemas = [SCIMSchema.ERROR.value]

        self._error_detail = ErrorDetail(scimType=scim_type, schemas=schemas, detail=detail, status=status_code)
        self._extra_headers: dict | None = None

    @property
    def error_detail(self) -> ErrorDetail:
        return self._error_detail

    @property
    def extra_headers(self) -> dict | None:
        return self._extra_headers

    @extra_headers.setter
    def extra_headers(self, headers: dict) -> None:
        self._extra_headers = headers


class BadRequest(HTTPErrorDetail):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = "Bad Request"


class Unauthorized(HTTPErrorDetail):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = "Unauthorized request"


class NotFound(HTTPErrorDetail):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = "Resource not found"


class MethodNotAllowedMalformed(HTTPErrorDetail):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(status_code=status.HTTP_405_METHOD_NOT_ALLOWED, **kwargs)
        if not self.error_detail.detail:
            allowed_methods = kwargs.get("allowed_methods")
            self.error_detail.detail = f"The used HTTP method is not allowed. Allowed methods: {allowed_methods}"


class UnsupportedMediaTypeMalformed(HTTPErrorDetail):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = "Request was made with an unsupported media type"


class Conflict(HTTPErrorDetail):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(status_code=status.HTTP_409_CONFLICT, **kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = "Request conflicts with the current state"
