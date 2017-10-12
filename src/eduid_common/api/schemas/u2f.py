# -*- coding: utf-8 -*-
from __future__ import absolute_import

from marshmallow import Schema, fields
from eduid_common.api.schemas.base import EduidSchema

__author__ = 'lundberg'


class U2FRegisteredKey(EduidSchema):

    version = fields.String(required=True)
    key_handle = fields.String(required=True, load_from='keyHandle', dump_to='keyHandle')
    app_id = fields.String(required=True, load_from='appId', dump_to='appId')
    transports = fields.String(required=False)


class U2FRegisterRequest(EduidSchema):

    version = fields.String(required=True)
    challenge = fields.String(required=True)


class U2FClientData(EduidSchema):

    typ = fields.String(required=True)
    challenge = fields.String(required=True)
    origin = fields.String(required=True)


class U2FEnrollResponseSchema(EduidSchema):

    app_id = fields.String(required=True, load_from='appId', dump_to='appId')
    registered_keys = fields.Nested(U2FRegisteredKey, required=True, missing=list(), load_from='registeredKeys',
                                    dump_to='registeredKeys', many=True)
    register_requests = fields.Nested(U2FRegisterRequest, required=True, load_from='registerRequests',
                                      dump_to='registerRequests', many=True)


class U2FBindRequestSchema(EduidSchema):

    version = fields.String(required=True)
    registration_data = fields.String(required=True, load_from='registrationData',
                                      dump_to='registrationData')
    client_data = fields.String(required=True, load_from='clientData',
                                dump_to='clientData')


class U2FSignResponseSchema(EduidSchema):

    app_id = fields.String(required=True, load_from='appId', dump_to='appId')
    registered_keys = fields.Nested(U2FRegisteredKey, required=True, missing=list(), load_from='registeredKeys',
                                    dump_to='registeredKeys', many=True)
    challenge = fields.String(required=True)


class U2FVerifyRequestSchema(EduidSchema):

    key_handle = fields.String(required=True, load_from='keyHandle', dump_to='keyHandle')
    signature_data = fields.String(required=True, load_from='signatureData', dump_to='signatureData')
    client_data = fields.String(required=True, load_from='clientData',
                                dump_to='clientData')


class U2FVerifyResponseSchema(EduidSchema):

    touch = fields.Integer(required=True)
    counter = fields.Integer(required=True)
