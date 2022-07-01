# -*- coding: utf-8 -*-
from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFResponseMixin

__author__ = 'lundberg'


class SvipeIDResultResponseSchema(FluxStandardAction):
    class SvipeIDResultResponsePayload(EduidSchema, CSRFResponseMixin):
        message = fields.String(required=True)

    payload = fields.Nested(SvipeIDResultResponsePayload)
