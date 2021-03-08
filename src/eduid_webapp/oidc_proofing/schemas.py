# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid_common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class OidcProofingRequestSchema(EduidSchema, CSRFRequestMixin):

    nin = fields.String(required=True, validate=validate_nin)


class NonceResponseSchema(FluxStandardAction):
    class NonceResponsePayload(EduidSchema, CSRFResponseMixin):
        qr_code = fields.String(required=True)
        qr_img = fields.String(required=True)

    payload = fields.Nested(NonceResponsePayload)


class FrejaResponseSchema(FluxStandardAction):
    class FrejaResponsePayload(EduidSchema, CSRFResponseMixin):
        iaRequestData = fields.String(required=True)

    payload = fields.Nested(FrejaResponsePayload)
