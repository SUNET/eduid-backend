# -*- coding: utf-8 -*-

from marshmallow import Schema, fields

__author__ = 'lundberg'


# Output validation
class NonceResponseSchema(Schema):

    class Meta:
        strict = True

    nonce = fields.String(required=True)
    qr_img = fields.String(required=True)


# TODO: Remove after demo stage
class ProofResponseSchema(Schema):

    proofs = fields.List(fields.Dict)
