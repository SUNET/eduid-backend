from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin

__author__ = "lundberg"


class AuthnCommonRequestSchema(EduidSchema, CSRFRequestMixin):
    """A verify request for either an identity or a credential proofing."""

    method = fields.String(required=True)
    frontend_action = fields.String(required=True)
    frontend_state = fields.String(required=False)


class AuthnCommonResponseSchema(FluxStandardAction):
    class AuthnCommonResponsePayload(EduidSchema, CSRFResponseMixin):
        location = fields.String(required=False)

    payload = fields.Nested(AuthnCommonResponsePayload)


class AuthnAuthenticateRequestSchema(AuthnCommonRequestSchema):
    same_user = fields.Boolean(required=False)
    force_authn = fields.Boolean(required=False)
    high_security = fields.Boolean(required=False)  # opportunistic MFA, request it if the user has a token
    force_mfa = fields.Boolean(required=False)  # require MFA even if the user has no token (use Freja or other)


class AuthnStatusRequestSchema(EduidSchema, CSRFRequestMixin):
    authn_id = fields.String(required=False)


class AuthnStatusResponseSchema(EduidSchema, CSRFResponseMixin):
    class StatusResponsePayload(EduidSchema, CSRFResponseMixin):
        authn_id = fields.String(required=False)
        frontend_action = fields.String(required=True)
        frontend_state = fields.String(required=False)
        method = fields.String(required=True)
        error = fields.Boolean(required=False)
        status = fields.String(required=False)

    payload = fields.Nested(StatusResponsePayload)
