from __future__ import annotations

import json
import logging
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

import falcon

from eduid.scimapi.schemas.scimbase import SCIMSchema
from eduid.scimapi.utils import filter_none

logger = logging.getLogger(__name__)


@dataclass
class ErrorDetail(object):
    scimType: Optional[str] = None
    schemas: List[str] = field(default_factory=lambda: [SCIMSchema.ERROR.value])
    detail: Optional[str] = None
    status: Optional[int] = None


# Catch and handle falcons default exceptions
def method_not_allowed_handler(ex: falcon.HTTPMethodNotAllowed, req: falcon.Request, resp: falcon.Response, params):
    orig_headers = ex.headers
    e = MethodNotAllowedMalformed(allowed_methods=orig_headers.get('Allow').split(','))
    e.extra_headers = orig_headers
    return e.handle(e, req, resp, params)


def unsupported_media_type_handler(
    ex: falcon.HTTPUnsupportedMediaType, req: falcon.Request, resp: falcon.Response, params
):
    e = UnsupportedMediaTypeMalformed(detail=ex.description)
    return e.handle(e, req, resp, params)


def unexpected_error_handler(ex: Exception, req: falcon.Request, resp: falcon.Response, params):
    error_id = uuid.uuid4()
    logger.error(f'Unexpected error {error_id}: {ex}')
    logger.error(traceback.format_exc())
    e = ServerInternal()
    e.error_detail.detail = f'Please reference the error id {error_id} when reporting this issue'
    return e.handle(e, req, resp, params)


class HTTPErrorDetail(falcon.HTTPError):
    def __init__(self, **kwargs):
        schemas = kwargs.pop('schemas', [SCIMSchema.ERROR.value])
        scim_type = kwargs.pop('scim_type', None)
        detail = kwargs.pop('detail', None)
        super().__init__(**kwargs)
        status = int(self.status.split(' ')[0])
        self._error_detail = ErrorDetail(scimType=scim_type, schemas=schemas, detail=detail, status=status)
        self._extra_headers: Optional[Dict] = None

    @property
    def error_detail(self) -> ErrorDetail:
        return self._error_detail

    @property
    def extra_headers(self):
        return self._extra_headers

    @extra_headers.setter
    def extra_headers(self, headers: Dict):
        self._extra_headers = headers

    def to_dict(self, obj_type=dict):
        result = filter_none(asdict(self._error_detail))
        return result

    @staticmethod
    def handle(ex: HTTPErrorDetail, req: falcon.Request, resp: falcon.Response, params):
        resp.status = ex.status
        resp.content_type = 'application/scim+json'
        resp.body = json.dumps(ex.to_dict())
        if ex.extra_headers:
            for key, value in ex.extra_headers.items():
                resp.set_header(key, value)


class BadRequest(HTTPErrorDetail, falcon.HTTPBadRequest):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = 'Bad Request'


class Unauthorized(HTTPErrorDetail, falcon.HTTPUnauthorized):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = 'Unauthorized request'


class NotFound(HTTPErrorDetail, falcon.HTTPNotFound):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = 'Resource not found'


class UnsupportedMediaTypeMalformed(HTTPErrorDetail, falcon.HTTPUnsupportedMediaType):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.error_detail.detail:
            self.error_detail.detail = 'Request was made with an unsupported media type'


class MethodNotAllowedMalformed(HTTPErrorDetail, falcon.HTTPMethodNotAllowed):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.error_detail.detail:
            allowed_methods = kwargs.get('allowed_methods')
            self.error_detail.detail = f'The used HTTP method is not allowed. Allowed methods: {allowed_methods}'


class ServerInternal(HTTPErrorDetail, falcon.HTTPInternalServerError):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
