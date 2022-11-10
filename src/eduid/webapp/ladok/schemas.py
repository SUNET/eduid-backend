# -*- coding: utf-8 -*-
from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.ladok import LadokSchema, University

__author__ = "lundberg"


class UniversityInfoResponseSchema(FluxStandardAction):
    class UniversityInfoPayload(EduidSchema, CSRFResponseMixin):
        universities = fields.Dict(keys=fields.String(), values=fields.Nested(University()))

    payload = fields.Nested(UniversityInfoPayload)


class LinkUserRequest(EduidSchema, CSRFRequestMixin):
    ladok_name = fields.String(required=True)


class LinkUserResponse(FluxStandardAction):
    class LinkUserPayload(EduidSchema, CSRFResponseMixin):
        ladok = fields.Nested(LadokSchema, attribute="ladok")

    payload = fields.Nested(LinkUserPayload)
