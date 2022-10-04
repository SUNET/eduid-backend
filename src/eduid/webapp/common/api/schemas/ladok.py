# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema

__author__ = "lundberg"


class UniversityName(EduidSchema):
    sv = fields.String()
    en = fields.String()


class University(EduidSchema):
    ladok_name = fields.String()
    name = fields.Nested(UniversityName())


class LadokSchema(EduidSchema):
    external_id = fields.String()
    university = fields.Nested(University())
