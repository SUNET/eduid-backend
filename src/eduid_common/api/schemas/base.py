# -*- coding: utf-8 -*-

from marshmallow import Schema, fields

__author__ = 'lundberg'


class FluxStandardAction(Schema):

    class Meta:
        strict = True

    type = fields.String(required=True)
    payload = fields.Raw(required=False)
    error = fields.Boolean(required=False)
    meta = fields.Raw(required=False)
