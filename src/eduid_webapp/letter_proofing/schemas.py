# -*- coding: utf-8 -*-

from marshmallow import Schema, fields
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class LetterProofingRequestSchema(Schema):

    class Meta:
        strict = True

    nin = fields.String(required=False, validate=validate_nin, missing=None)


class VerifyCodeRequestSchema(Schema):

    class Meta:
        strict = True

    verification_code = fields.String(required=True)


class LetterProofingResponseSchema(FluxStandardAction):

    class LetterProofingPayload(Schema):
        letter_sent = fields.DateTime(format='%s')
        letter_expires = fields.DateTime(format='%s')
        letter_expired = fields.Boolean()

    payload = fields.Nested(LetterProofingPayload)


class VerifyCodeResponseSchema(FluxStandardAction):

    class VerifyCodePayload(Schema):
        success = fields.Boolean(required=True)
        message = fields.String(required=False)

    payload = fields.Nested(VerifyCodePayload)


class LetterProofingDataSchema(Schema):

    class Meta:
        strict = True

    number = fields.String(required=True)
    created_by = fields.String(required=True)
    created_ts = fields.DateTime(required=True, format='%s')
    verified = fields.Boolean(required=True)
    verified_by = fields.String(required=True)
    verified_ts = fields.DateTime(required=True, format='%s')
    verification_code = fields.String(required=True)
    official_address = fields.Dict(required=True)
    transaction_id = fields.String(required=True)