from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.orcid import OrcidSchema


class OrcidConnectRequestSchema(EduidSchema, CSRFRequestMixin):
    frontend_action = fields.String(required=True)
    frontend_state = fields.String(required=False, load_default=None)


class OrcidConnectResponseSchema(FluxStandardAction):
    class OrcidConnectResponsePayload(EduidSchema, CSRFResponseMixin):
        location = fields.String(required=False)

    payload = fields.Nested(OrcidConnectResponsePayload)


class OrcidResponseSchema(FluxStandardAction):
    class OrcidResponsePayload(EduidSchema, CSRFResponseMixin):
        orcid = fields.Nested(OrcidSchema)

    payload = fields.Nested(OrcidResponsePayload)
