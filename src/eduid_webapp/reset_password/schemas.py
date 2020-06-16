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
from marshmallow import ValidationError, fields, validates

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid_common.api.schemas.password import PasswordSchema
from eduid_common.api.schemas.validators import validate_email

from eduid_webapp.reset_password.helpers import ResetPwMsg
from eduid_webapp.security.schemas import CredentialSchema

__author__ = 'eperez'


class ResetPasswordInitSchema(EduidSchema, CSRFRequestMixin):

    email = fields.String(required=True)

    @validates('email')
    def validate_email_field(self, value, **kwargs):
        # Set a new error message
        try:
            validate_email(value)
        except ValidationError:
            raise ValidationError(ResetPwMsg.invalid_email.value)


class ResetPasswordEmailCodeSchema(EduidSchema, CSRFRequestMixin):

    code = fields.String(required=True)


class ResetPasswordExtraSecPhoneSchema(EduidSchema, CSRFRequestMixin):

    code = fields.String(required=True)
    phone_index = fields.Integer(required=True)


class ResetPasswordWithCodeSchema(EduidSchema, CSRFRequestMixin):

    code = fields.String(required=True)
    password = fields.String(required=True)


class ResetPasswordWithPhoneCodeSchema(ResetPasswordWithCodeSchema):

    phone_code = fields.String(required=True)


class ResetPasswordWithSecTokenSchema(ResetPasswordWithCodeSchema):

    credentialId = fields.String(required=True)
    authenticatorData = fields.String(required=True)
    clientDataJSON = fields.String(required=True)
    signature = fields.String(required=True)


class ChpassCredentialList(EduidSchema, CSRFResponseMixin):
    credentials = fields.Nested(CredentialSchema, many=True)
    next_url = fields.String(required=True)


class ChpassResponseSchema(FluxStandardAction):
    payload = fields.Nested(ChpassCredentialList)


class ChpassRequestSchema(EduidSchema, CSRFRequestMixin):

    old_password = fields.String(required=True)
    new_password = fields.String(required=True)


class SuggestedPassword(EduidSchema, CSRFResponseMixin):

    suggested_password = fields.String(required=True)


class SuggestedPasswordResponseSchema(FluxStandardAction):

    payload = fields.Nested(SuggestedPassword, many=False)


class NewPasswordSecurePhoneRequestSchema(EduidSchema, CSRFRequestMixin):

    code = fields.String(required=True)
    password = fields.String(required=True)
    phone_code = fields.String(required=True)


class NewPasswordSecureTokenRequestSchema(EduidSchema, CSRFRequestMixin):

    code = fields.String(required=True)
    password = fields.String(required=True)
    tokenResponse = fields.String(required=False)
    authenticatorData = fields.String(required=False)
    clientDataJSON = fields.String(required=False)
    credentialId = fields.String(required=False)
    signature = fields.String(required=False)
