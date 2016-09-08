# -*- coding: utf-8 -*-

from marshmallow import Schema, fields
from eduid_common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class ProofingRequestSchema(Schema):

    class Meta:
        strict = True

    nin = fields.String(required=False, validate=validate_nin)


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
