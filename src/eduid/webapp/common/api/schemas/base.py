from marshmallow import RAISE, Schema, fields

__author__ = "lundberg"


class EduidSchema(Schema):
    message = fields.String(required=False)

    class Meta:
        unknown = RAISE  # Raise ValidationError on unknown data


class FluxStandardAction(EduidSchema):
    type = fields.String(required=True)
    payload: fields.Field = fields.Field(required=False)
    error = fields.Boolean(required=False)
    meta = fields.Raw(required=False)
