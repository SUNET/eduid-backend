from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema

__author__ = "lundberg"


class IdentitySchema(EduidSchema):
    verified = fields.Boolean(required=True)


class NinIdentitySchema(IdentitySchema):
    number = fields.String(required=True)


class ForeignIdentitySchema(IdentitySchema):
    date_of_birth = fields.Date(required=True)
    country_code = fields.String(required=True)


class IdentitiesSchema(EduidSchema):
    is_verified = fields.Boolean(required=True)
    nin = fields.Nested(NinIdentitySchema)
    eidas = fields.Nested(ForeignIdentitySchema)
    svipe = fields.Nested(ForeignIdentitySchema)
