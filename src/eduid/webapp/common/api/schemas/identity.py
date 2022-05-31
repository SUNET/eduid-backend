# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema

__author__ = 'lundberg'


class IdentitySchema(EduidSchema):
    verified = fields.Boolean(required=True)


class NinIdentitySchema(IdentitySchema):
    number = fields.String(required=True)


class EidasIdentitySchema(IdentitySchema):
    date_of_birth = fields.Date(required=True)
    country = fields.String(required=True)


class IdentitiesSchema(EduidSchema):
    is_verified = fields.Boolean(required=True)
    nin = fields.Nested(NinIdentitySchema)
    eidas = fields.Nested(EidasIdentitySchema)


# TODO: Remove after frontend uses identities
class NinSchema(EduidSchema):
    number = fields.String(required=True)
    verified = fields.Boolean(required=True)
    primary = fields.Boolean(required=True)
