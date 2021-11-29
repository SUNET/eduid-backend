# -*- coding: utf-8 -*-
from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class University(EduidSchema):
    abbr = fields.String(required=True)
    name_sv = fields.String(allow_none=True)
    name_en = fields.String(allow_none=True)


class UniversityInfoResponseSchema(FluxStandardAction):
    class UniversityInfoPayload(EduidSchema, CSRFResponseMixin):
        universities = fields.Nested(University, many=True)

    payload = fields.Nested(UniversityInfoPayload)


class LinkUserRequest(EduidSchema, CSRFRequestMixin):
    university_abbr = fields.String(required=True)
