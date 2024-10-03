import logging
from typing import Any

from flask import current_app, request
from marshmallow import Schema, ValidationError, fields, post_load, pre_dump, validates

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.session import session

__author__ = "lundberg"

logger = logging.getLogger(__name__)


class CSRFRequestMixin(Schema):
    csrf_token = fields.String(required=True)

    @validates("csrf_token")
    def validate_csrf_token(self, value: str, **kwargs: Any) -> None:
        custom_header = request.headers.get("X-Requested-With")
        if custom_header != "XMLHttpRequest":  # TODO: move value to config
            current_app.logger.error("CSRF check: missing custom X-Requested-With header")
            raise ValidationError("CSRF missing custom X-Requested-With header")
        if session.get_csrf_token() != value:
            raise ValidationError("CSRF failed to validate")
        logger.debug(f"Validated CSRF token in session: {session.get_csrf_token()}")

    @post_load
    def post_processing(self, in_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        # Remove token from data forwarded to views
        in_data = self.remove_csrf_token(in_data)
        return in_data

    @staticmethod
    def remove_csrf_token(in_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        del in_data["csrf_token"]
        return in_data


class CSRFResponseMixin(Schema):
    csrf_token = fields.String(required=True)

    @pre_dump
    def get_csrf_token(self, out_data: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        # Generate a new csrf token for every response
        out_data["csrf_token"] = session.new_csrf_token()
        logger.debug(f'Generated new CSRF token in CSRFResponseMixin: {out_data["csrf_token"]}')
        return out_data


class EmptyRequest(EduidSchema, CSRFRequestMixin):
    """This is a common request schema that will just check the CSRF token"""

    pass


class EmptyResponse(FluxStandardAction):
    """This is a common response schema for returning an empty response with a fresh CSRF token"""

    class ResponsePayload(EduidSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(ResponsePayload)
