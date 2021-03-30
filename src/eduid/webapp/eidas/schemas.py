# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin

__author__ = 'lundberg'


class EidasTokenVerifyRequestSchema(EduidSchema, CSRFRequestMixin):
    credential_id = fields.String(required=True)


class EidasResponseSchema(EduidSchema, CSRFResponseMixin):
    pass
