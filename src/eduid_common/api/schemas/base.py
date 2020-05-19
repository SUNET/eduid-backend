# -*- coding: utf-8 -*-

from marshmallow import Schema, RAISE, ValidationError, fields, validates_schema

__author__ = 'lundberg'


class EduidSchema(Schema):

    message = fields.String(required=False)

    class Meta:
        unknown = RAISE  # Raise ValidationError on unknown data


class FluxStandardAction(EduidSchema):

    type = fields.String(required=True)
    payload = fields.Raw(required=False)
    error = fields.Boolean(required=False)
    meta = fields.Raw(required=False)
