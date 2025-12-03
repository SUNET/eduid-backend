from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin

__author__ = "lundberg"


class SamleidCommonRequestSchema(EduidSchema, CSRFRequestMixin):
    """A verify request for either an identity or a credential proofing."""

    method = fields.String(required=True)
    frontend_action = fields.String(required=True)
    frontend_state = fields.String(required=False)


class SamleidCommonResponseSchema(FluxStandardAction):
    class VerifyResponsePayload(EduidSchema, CSRFResponseMixin):
        location = fields.String(required=False)
        credential_description = fields.String(required=False)

    payload = fields.Nested(VerifyResponsePayload)


class SamleidVerifyCredentialRequestSchema(SamleidCommonRequestSchema):
    credential_id = fields.String(required=True)


class SamleidStatusRequestSchema(EduidSchema, CSRFRequestMixin):
    authn_id = fields.String(required=False)


class SamleidStatusResponseSchema(EduidSchema, CSRFResponseMixin):
    class StatusResponsePayload(EduidSchema, CSRFResponseMixin):
        authn_id = fields.String(required=False)
        frontend_action = fields.String(required=True)
        frontend_state = fields.String(required=False)
        method = fields.String(required=True)
        error = fields.Boolean(required=False)
        status = fields.String(required=False)

    payload = fields.Nested(StatusResponsePayload)
