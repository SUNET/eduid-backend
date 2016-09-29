# -*- coding: utf-8 -*-

from marshmallow import Schema, fields
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class OidcProofingRequestSchema(Schema):

    class Meta:
        strict = True

    nin = fields.String(required=True, validate=validate_nin)


class NonceResponseSchema(FluxStandardAction):

    class NonceResponsePayload(Schema):
        nonce = fields.String(required=True)
        qrcode = fields.String(required=True)

    payload = fields.Nested(NonceResponsePayload)


# TODO: Remove after demo stage
class ProofResponseSchema(Schema):

    proofs = fields.List(fields.Dict)
