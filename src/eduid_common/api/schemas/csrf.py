# -*- coding: utf-8 -*-

from __future__ import absolute_import

from marshmallow import Schema, fields, validates, pre_dump, post_load, ValidationError
from flask import session
from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction

__author__ = 'lundberg'


class CSRFRequestMixin(Schema):

    csrf_token = fields.String(required=True)

    @validates('csrf_token')
    def validate_csrf_token(self, value):
        if session.get_csrf_token() != value:
            raise ValidationError('CSRF failed to validate')

    @post_load
    def post_processing(self, in_data):
        # Generate a new csrf token after use
        session.new_csrf_token()
        # Remove token from data forwarded to views
        in_data = self.remove_csrf_token(in_data)
        return in_data

    @staticmethod
    def remove_csrf_token(in_data):
        del in_data['csrf_token']
        return in_data


class CSRFResponseMixin(Schema):

    csrf_token = fields.String(required=True)

    @pre_dump
    def get_csrf_token(self, out_data):
        out_data['csrf_token'] = session.get_csrf_token()
        return out_data


class CSRFRequest(EduidSchema):

    class RequestPayload(EduidSchema, CSRFRequestMixin):
        pass

    payload = fields.Nested(RequestPayload)


class CSRFResponse(FluxStandardAction):

    class ResponsePayload(EduidSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(ResponsePayload)

    @pre_dump
    def add_payload_if_missing(self, out_data):
        if not out_data.get('payload'):
            out_data['payload'] = {'csrf_token': None}
        return out_data

