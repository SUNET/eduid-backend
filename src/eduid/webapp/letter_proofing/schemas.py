from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.identity import IdentitiesSchema
from eduid.webapp.common.api.schemas.validators import validate_nin

__author__ = "lundberg"


class LetterProofingRequestSchema(EduidSchema, CSRFRequestMixin):
    nin = fields.String(required=True, validate=validate_nin)


class VerifyCodeRequestSchema(EduidSchema, CSRFRequestMixin):
    code = fields.String(required=True)


class LetterProofingResponseSchema(FluxStandardAction):
    class Meta:
        strict = True

    class LetterProofingPayload(EduidSchema, CSRFResponseMixin):
        letter_sent = fields.DateTime()
        letter_expires = fields.DateTime()
        letter_expired = fields.Boolean()
        letter_expires_in_days = fields.Int(required=False)
        letter_sent_days_ago = fields.Int(required=False)

    payload = fields.Nested(LetterProofingPayload)


class VerifyCodeResponseSchema(FluxStandardAction):
    class VerifyCodePayload(EduidSchema, CSRFResponseMixin):
        success = fields.Boolean(required=True)
        message = fields.String(required=False)
        identities = fields.Nested(IdentitiesSchema)

    payload = fields.Nested(VerifyCodePayload)
