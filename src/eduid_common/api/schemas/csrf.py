# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app, request
from marshmallow import Schema, ValidationError, fields, post_load, pre_dump, validates
from six.moves.urllib.parse import urlsplit

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.session import session

__author__ = 'lundberg'


class CSRFRequestMixin(Schema):

    csrf_token = fields.String(required=True)

    @validates('csrf_token')
    def validate_csrf_token(self, value, **kwargs):
        custom_header = request.headers.get('X-Requested-With', '')
        if custom_header != 'XMLHttpRequest':
            raise ValidationError('CSRF missing custom X-Requested-With header')
        origin = request.headers.get('Origin', None)
        if origin is None:
            origin = request.headers.get('Referer', None)
        if origin is None:
            raise ValidationError('CSRF cannot check origin')
        origin = origin.split()[0]
        origin = urlsplit(origin).hostname
        target = request.headers.get('X-Forwarded-Host', None)
        if target is None:
            current_app.logger.error('The X-Forwarded-Host header is missing!!')
            raise ValidationError('CSRF cannot check target')
        target = target.split(':')[0]
        if origin != target:
            raise ValidationError('CSRF cross origin request, origin: {}, ' 'target: {}'.format(origin, target))
        if session.get_csrf_token() != value:
            raise ValidationError('CSRF failed to validate')

    @post_load
    def post_processing(self, in_data, **kwargs):
        # Remove token from data forwarded to views
        in_data = self.remove_csrf_token(in_data)
        return in_data

    @staticmethod
    def remove_csrf_token(in_data, **kwargs):
        del in_data['csrf_token']
        return in_data


class CSRFResponseMixin(Schema):

    csrf_token = fields.String(required=True)

    @pre_dump
    def get_csrf_token(self, out_data, **kwargs):
        # Generate a new csrf token for every response
        out_data['csrf_token'] = session.new_csrf_token()
        return out_data


class CSRFRequest(EduidSchema, CSRFRequestMixin):
    pass


class CSRFResponse(FluxStandardAction):
    class ResponsePayload(EduidSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(ResponsePayload)

    @pre_dump
    def add_payload_if_missing(self, out_data, **kwargs):
        if not out_data.get('payload'):
            out_data['payload'] = {'csrf_token': None}
        return out_data
