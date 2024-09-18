from enum import Enum, unique

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin

__author__ = "lundberg"


@unique
class AuthnActionStatus(Enum):
    OK = "ok"
    NOT_FOUND = "not-found"
    CONSUMED = "consumed"
    STALE = "stale"
    WRONG_ACCR = "wrong-accr"
    NO_MFA = "no-mfa"
    CREDENTIAL_NOT_RECENTLY_USED = "credential-not-recently-used"


class StatusRequestSchema(EduidSchema, CSRFRequestMixin):
    authn_id = fields.String(required=False)


class StatusResponseSchema(FluxStandardAction, CSRFResponseMixin):
    class StatusResponsePayload(EduidSchema, CSRFResponseMixin):
        frontend_action = fields.String(required=True)
        frontend_state = fields.String(required=False)
        method = fields.String(required=True)
        error = fields.Boolean(required=False)
        status = fields.String(required=False)

    payload = fields.Nested(StatusResponsePayload)
