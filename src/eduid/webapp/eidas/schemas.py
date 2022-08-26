# -*- coding: utf-8 -*-
from typing import Optional

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin

__author__ = 'lundberg'

from eduid.webapp.eidas.helpers import EidasMsg


class EidasTokenVerifyRequestSchema(EduidSchema, CSRFRequestMixin):
    credential_id = fields.String(required=True)


class EidasResponseSchema(EduidSchema, CSRFResponseMixin):
    pass


class EidasVerifyRequestSchema(EduidSchema, CSRFRequestMixin):
    """A verify request for either an identity or a credential proofing."""

    method = fields.String(required=True)
    frontend_action = fields.String(required=True)
    frontend_state = fields.String(required=False)


class EidasVerifyResponseSchema(EduidSchema, CSRFResponseMixin):
    location = fields.String(required=False)


class EidasVerifyTokenRequestSchema(EidasVerifyRequestSchema):
    credential_id = fields.String(required=True)


class EidasVerifyTokenResponseSchema(EidasVerifyResponseSchema):
    pass


class EidasStatusRequestSchema(EduidSchema, CSRFResponseMixin):
    authn_id = fields.String(required=False)


class EidasStatusResponseSchema(EduidSchema, CSRFResponseMixin):
    frontend_action = fields.String(required=True)
    frontend_state = fields.String(required=False)
