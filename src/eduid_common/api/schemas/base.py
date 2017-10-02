# -*- coding: utf-8 -*-

from marshmallow import Schema, fields, validates_schema, ValidationError

__author__ = 'lundberg'


class EduidSchema(Schema):

    message = fields.String(required=False)

    class Meta:
        strict = True

    @validates_schema(pass_original=True)
    def check_unknown_fields(self, data, original_data):
        for key in data:
            if key not in self.fields:
                raise ValidationError('Unknown field name: {!s}'.format(key))


class FluxStandardAction(EduidSchema):

    type = fields.String(required=True)
    payload = fields.Raw(required=False)
    error = fields.Boolean(required=False)
    meta = fields.Raw(required=False)
