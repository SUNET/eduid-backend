# -*- coding: utf-8 -*-

from marshmallow import Schema, fields

__author__ = 'lundberg'


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
