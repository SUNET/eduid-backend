# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema

__author__ = 'lundberg'


class OrcidSchema(EduidSchema):
    id = fields.String()
    name = fields.String()
    given_name = fields.String()
    family_name = fields.String()
