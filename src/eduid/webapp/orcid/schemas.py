# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.common.api.schemas.csrf import CSRFResponseMixin
from eduid.common.api.schemas.orcid import OrcidSchema

__author__ = 'lundberg'


class OrcidResponseSchema(FluxStandardAction):
    class OrcidResponsePayload(EduidSchema, CSRFResponseMixin):
        orcid = fields.Nested(OrcidSchema)

    payload = fields.Nested(OrcidResponsePayload)
