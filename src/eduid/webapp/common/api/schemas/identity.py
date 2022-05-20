# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema

__author__ = 'lundberg'


class IdentitySchema(EduidSchema):
    identity_type = fields.String(required=True)
    number = fields.String(required=False)
    prid = fields.String(required=False)
    prid_persistence = fields.String(required=False)
    verified = fields.Boolean(required=True)
