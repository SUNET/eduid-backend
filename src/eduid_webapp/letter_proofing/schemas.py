# -*- coding: utf-8 -*-

from marshmallow import fields
from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class LetterProofingRequestSchema(EduidSchema):

    nin = fields.String(required=True, validate=validate_nin)


class VerifyCodeRequestSchema(EduidSchema):

    verification_code = fields.String(required=True)


class LetterProofingResponseSchema(FluxStandardAction):

    class Meta:
        strict = True

    class LetterProofingPayload(EduidSchema):
        letter_sent = fields.DateTime(format='%s')
        letter_expires = fields.DateTime(format='%s')
        letter_expired = fields.Boolean()

    payload = fields.Nested(LetterProofingPayload)


class VerifyCodeResponseSchema(FluxStandardAction):

    class VerifyCodePayload(EduidSchema):
        success = fields.Boolean(required=True)
        message = fields.String(required=False)

    payload = fields.Nested(VerifyCodePayload)


class LetterProofingDataSchema(EduidSchema):

    number = fields.String(required=True)
    created_by = fields.String(required=True)
    created_ts = fields.DateTime(required=True, format='%s')
    verified = fields.Boolean(required=True)
    verified_by = fields.String(required=True)
    verified_ts = fields.DateTime(required=True, format='%s')
    verification_code = fields.String(required=True)
    official_address = fields.Dict(required=True)
    transaction_id = fields.String(required=True)