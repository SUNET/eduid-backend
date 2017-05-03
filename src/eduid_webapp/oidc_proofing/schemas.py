# -*- coding: utf-8 -*-

from marshmallow import fields
from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class OidcProofingRequestSchema(EduidSchema):

    nin = fields.String(required=True, validate=validate_nin)


class NonceResponseSchema(FluxStandardAction):

    class NonceResponsePayload(EduidSchema):
        qr_code = fields.String(required=True)
        qr_img = fields.String(required=True)

    payload = fields.Nested(NonceResponsePayload)


class OpaqueResponseSchema(FluxStandardAction):

    class OpaqueResponsePayload(EduidSchema):
        opaque = fields.String(required=True)

    payload = fields.Nested(OpaqueResponsePayload)


# TODO: Remove after demo stage
class ProofResponseSchema(EduidSchema):

    proofs = fields.List(fields.Dict)
