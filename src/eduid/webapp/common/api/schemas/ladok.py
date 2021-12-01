# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema

__author__ = 'lundberg'


class UniversitySchema(EduidSchema):
    abbr = fields.String()
    name_sv = fields.String()
    name_en = fields.String()


class LadokSchema(EduidSchema):
    external_id = fields.String()
    university = fields.Nested(UniversitySchema())
