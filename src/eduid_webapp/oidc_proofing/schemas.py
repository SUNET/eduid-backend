# -*- coding: utf-8 -*-

from marshmallow import fields
from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class OidcProofingRequestSchema(EduidSchema):

    nin = fields.String(required=True, validate=validate_nin)


class NonceResponseSchema(FluxStandardAction):

    class NonceResponsePayload(EduidSchema):
        nonce = fields.String(required=True)
        qrcode = fields.String(required=True)

    payload = fields.Nested(NonceResponsePayload)


# TODO: Remove after demo stage
class ProofResponseSchema(EduidSchema):

    proofs = fields.List(fields.Dict)
