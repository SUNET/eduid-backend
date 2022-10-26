# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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
#     3. Neither the name of SUNET nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
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
from marshmallow import fields

from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.email import LowercaseEmail

__author__ = "eperez"


class ResetPasswordEmailRequestSchema(EduidSchema, CSRFRequestMixin):

    email = LowercaseEmail(required=True)


class ResetPasswordEmailCodeRequestSchema(EduidSchema, CSRFRequestMixin):

    email_code = fields.String(required=True)


class ResetPasswordEmailResponseSchema(FluxStandardAction):
    class ResetPasswordEmailResponsePayload(EduidSchema, CSRFResponseMixin):
        email = LowercaseEmail(required=True)
        email_code_timeout = fields.Int(required=True)
        throttled_seconds = fields.Int(required=True)
        throttled_max = fields.Int(required=True)

    payload = fields.Nested(ResetPasswordEmailResponsePayload)


class ResetPasswordResponseSchema(FluxStandardAction):
    class ResetPasswordResponsePayload(EduidSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(ResetPasswordResponsePayload)


class ResetPasswordVerifyEmailResponseSchema(FluxStandardAction):
    class ResetPasswordVerifyEmailResponsePayload(EduidSchema, CSRFResponseMixin):
        suggested_password = fields.String(required=True)
        email_code = fields.String(required=True)
        email_address = fields.String(required=True)
        extra_security = fields.Dict(required=True)
        success = fields.Bool(required=True)
        zxcvbn_terms = fields.List(required=True, cls_or_instance=fields.String)

    payload = fields.Nested(ResetPasswordVerifyEmailResponsePayload)


class ResetPasswordExtraSecPhoneSchema(EduidSchema, CSRFRequestMixin):

    email_code = fields.String(required=True)
    phone_index = fields.Integer(required=True)


class ResetPasswordWithCodeSchema(EduidSchema, CSRFRequestMixin):

    email_code = fields.String(required=True)
    password = fields.String(required=True)


class ResetPasswordWithPhoneCodeSchema(ResetPasswordWithCodeSchema):

    phone_code = fields.String(required=True)


class ResetPasswordWithSecTokenSchema(ResetPasswordWithCodeSchema):

    authenticator_data = fields.String(required=False, data_key="authenticatorData")
    client_data_json = fields.String(required=False, data_key="clientDataJSON")
    credential_id = fields.String(required=False, data_key="credentialId")
    signature = fields.String(required=True)


class SuggestedPasswordResponseSchema(FluxStandardAction):
    class SuggestedPasswordPayload(EduidSchema, CSRFResponseMixin):
        suggested_password = fields.String(required=True)

    payload = fields.Nested(SuggestedPasswordPayload, many=False)


class NewPasswordSecurePhoneRequestSchema(EduidSchema, CSRFRequestMixin):

    email_code = fields.String(required=True)
    password = fields.String(required=True)
    phone_code = fields.String(required=True)


class NewPasswordSecureTokenRequestSchema(EduidSchema, CSRFRequestMixin):

    email_code = fields.String(required=True)
    password = fields.String(required=True)
    token_response = fields.String(required=False, data_key="tokenResponse")
    authenticator_data = fields.String(required=False, data_key="authenticatorData")
    client_data_json = fields.String(required=False, data_key="clientDataJSON")
    credential_id = fields.String(required=False, data_key="credentialId")
    signature = fields.String(required=False)
