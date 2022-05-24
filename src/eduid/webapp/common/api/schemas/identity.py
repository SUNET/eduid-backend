# -*- coding: utf-8 -*-

from marshmallow import fields
from marshmallow_oneofschema import OneOfSchema

from eduid.userdb.identity import IdentityType
from eduid.webapp.common.api.schemas.base import EduidSchema

__author__ = 'lundberg'


class IdentitySchema(EduidSchema):
    identity_type = fields.String(required=True)
    verified = fields.Boolean(required=True)


class NinIdentitySchema(IdentitySchema):
    number = fields.String(required=True)


class EidasIdentitySchema(IdentitySchema):
    date_of_birth = fields.Date(required=True)
    country = fields.String(required=True)


class AnyIdentitySchema(OneOfSchema):
    type_field = 'identity_type'
    type_schemas = {IdentityType.NIN.value: NinIdentitySchema, IdentityType.EIDAS.value: EidasIdentitySchema}

    def get_obj_type(self, obj):
        return obj['identity_type']


# TODO: Remove after frontend uses identities
class NinSchema(EduidSchema):
    number = fields.String(required=True)
    verified = fields.Boolean(required=True)
    primary = fields.Boolean(required=True)
