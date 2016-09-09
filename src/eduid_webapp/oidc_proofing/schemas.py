# -*- coding: utf-8 -*-

from marshmallow import Schema, fields
from eduid_common.api.schemas.base import FluxStandardAction
from eduid_common.api.schemas.proofing import ProofingRequestSchema

__author__ = 'lundberg'


class OidcProofingRequestSchema(ProofingRequestSchema):
    pass


class NonceResponseSchema(FluxStandardAction):

    class NonceResponsePayload(Schema):
        nonce = fields.String(required=True)
        qr_img = fields.String(required=True)

    payload = fields.Nested(NonceResponsePayload)


# TODO: Remove after demo stage
class ProofResponseSchema(Schema):

    proofs = fields.List(fields.Dict)
