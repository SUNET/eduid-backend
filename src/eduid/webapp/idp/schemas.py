# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

from marshmallow import Schema, fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin

__author__ = 'ft'


class IdPRequest(EduidSchema, CSRFRequestMixin):
    ref = fields.Str(required=True)


class NextRequestSchema(IdPRequest):
    pass


class NextResponseSchema(FluxStandardAction):
    class NextResponsePayload(EduidSchema, CSRFResponseMixin):
        action = fields.Str(required=True)
        target = fields.Str(required=True)
        parameters = fields.Dict(keys=fields.Str(), values=fields.Str(), required=False)

    payload = fields.Nested(NextResponsePayload)


class PwAuthRequestSchema(IdPRequest):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class PwAuthResponseSchema(FluxStandardAction):
    class PwAuthResponsePayload(EduidSchema, CSRFResponseMixin):
        finished = fields.Bool(required=True)

    payload = fields.Nested(PwAuthResponsePayload)


class AuthnOptionsRequestSchema(IdPRequest):
    pass


class AuthnOptionsResponseSchema(FluxStandardAction):
    class AuthnOptionsResponsePayload(EduidSchema, CSRFResponseMixin):
        password = fields.Bool(required=True)
        webauthn = fields.Bool(required=True)
        freja_eidplus = fields.Bool(required=True)
        other_device = fields.Bool(required=True)
        username = fields.Str(required=False)

    payload = fields.Nested(AuthnOptionsResponsePayload)


class MfaAuthRequestSchema(IdPRequest):
    webauthn_response = fields.Dict(keys=fields.Str(), values=fields.Str(), default=None, required=False)


class MfaAuthResponseSchema(FluxStandardAction):
    class MfaAuthResponsePayload(EduidSchema, CSRFResponseMixin):
        finished = fields.Bool(required=True)
        webauthn_options = fields.Str(required=False)

    payload = fields.Nested(MfaAuthResponsePayload)


class TouRequestSchema(IdPRequest):
    versions = fields.Str(required=False, many=True)
    user_accepts = fields.Str(required=False)


class TouResponseSchema(FluxStandardAction):
    class TouResponsePayload(EduidSchema, CSRFResponseMixin):
        finished = fields.Bool(required=True)
        version = fields.Str(required=False)

    payload = fields.Nested(TouResponsePayload)


class RequestOtherRequestSchema(IdPRequest):
    username = fields.Str(required=False)  # optional username, if the user supplies an e-mail address


class RequestOtherResponseSchema(FluxStandardAction):
    class RequestOtherResponsePayload(EduidSchema, CSRFResponseMixin):
        expires_in = fields.Int(required=True)  # to use expires_at, the client clock have to be in sync with backend
        expires_max = fields.Int(required=True)  # to use expires_at, the client clock have to be in sync with backend
        other_url = fields.Str(required=True)  # the link to where the user can manually enter short_code to proceed
        qr_img = fields.Str(required=True)
        short_code = fields.Str(required=True)
        state_id = fields.UUID(required=True)

    payload = fields.Nested(RequestOtherResponsePayload)


class UseOtherRequestSchema(EduidSchema, CSRFRequestMixin):
    state_id = fields.Str(required=True)


class UseOtherResponseSchema(FluxStandardAction):
    class UseOtherResponsePayload(EduidSchema, CSRFResponseMixin):
        class DeviceInfo(Schema):
            addr = fields.Str(required=True)
            description = fields.Str(required=False)
            proximity = fields.Str(required=False)

        device1_info = fields.Nested(DeviceInfo)
        expires_in = fields.Int(required=True)  # to use expires_at, the client clock have to be in sync with backend
        expires_max = fields.Int(required=True)  # to use expires_at, the client clock have to be in sync with backend
        short_code = fields.Str(required=True)
        login_ref = fields.Str(required=True)  # newly minted login_ref

    payload = fields.Nested(UseOtherResponsePayload)
