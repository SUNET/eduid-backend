# -*- coding: utf-8 -*-
from __future__ import absolute_import

from marshmallow import fields

from eduid.common.api.schemas.base import EduidSchema

__author__ = 'lundberg'


class U2FRegisteredKey(EduidSchema):

    version = fields.String(required=True)
    key_handle = fields.String(required=True, data_key='keyHandle')
    app_id = fields.String(required=True, data_key='appId')
    transports = fields.String(required=False)


class U2FRegisterRequest(EduidSchema):

    version = fields.String(required=True)
    challenge = fields.String(required=True)


class U2FClientData(EduidSchema):

    typ = fields.String(required=True)
    challenge = fields.String(required=True)
    origin = fields.String(required=True)


class U2FEnrollResponseSchema(EduidSchema):

    app_id = fields.String(required=True, data_key='appId')
    registered_keys = fields.Nested(
        U2FRegisteredKey, required=True, default=list(), data_key='registeredKeys', many=True
    )
    register_requests = fields.Nested(U2FRegisterRequest, required=True, data_key='registerRequests', many=True)


class U2FBindRequestSchema(EduidSchema):

    version = fields.String(required=True)
    registration_data = fields.String(required=True, data_key='registrationData')
    client_data = fields.String(required=True, data_key='clientData')


class U2FSignResponseSchema(EduidSchema):

    app_id = fields.String(required=True, data_key='appId')
    registered_keys = fields.Nested(
        U2FRegisteredKey, required=True, default=list(), data_key='registeredKeys', many=True
    )
    challenge = fields.String(required=True)


class U2FVerifyRequestSchema(EduidSchema):

    key_handle = fields.String(required=True, data_key='keyHandle')
    signature_data = fields.String(required=True, data_key='signatureData')
    client_data = fields.String(required=True, data_key='clientData')


class U2FVerifyResponseSchema(EduidSchema):

    key_handle = fields.String(required=True, data_key='keyHandle')
    touch = fields.Integer(required=True)
    counter = fields.Integer(required=True)
