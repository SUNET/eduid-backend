# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid_common.api.schemas.validators import validate_nin

from eduid_webapp.personal_data.schemas import NinSchema

__author__ = 'lundberg'


class LetterProofingRequestSchema(EduidSchema, CSRFRequestMixin):

    nin = fields.String(required=True, validate=validate_nin)


class VerifyCodeRequestSchema(EduidSchema, CSRFRequestMixin):

    code = fields.String(required=True)


class LetterProofingResponseSchema(FluxStandardAction):
    class Meta:
        strict = True

    class LetterProofingPayload(EduidSchema, CSRFResponseMixin):
        letter_sent = fields.DateTime(format='%s')
        letter_expires = fields.DateTime(format='%s')
        letter_expired = fields.Boolean()

    payload = fields.Nested(LetterProofingPayload)


class VerifyCodeResponseSchema(FluxStandardAction):
    class VerifyCodePayload(EduidSchema, CSRFResponseMixin):
        success = fields.Boolean(required=True)
        message = fields.String(required=False)
        nins = fields.Nested(NinSchema, many=True)

    payload = fields.Nested(VerifyCodePayload)
