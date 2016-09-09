# -*- coding: utf-8 -*-

from marshmallow import Schema, fields
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.schemas.proofing import ProofingRequestSchema

__author__ = 'lundberg'


class LetterProofingRequestSchema(ProofingRequestSchema):
    pass


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
