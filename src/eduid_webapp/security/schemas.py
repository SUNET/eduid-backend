# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
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
#     3. Neither the name of the NORDUnet nor the names of its
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

from __future__ import absolute_import

from flask_babel import gettext as _
from marshmallow import Schema, ValidationError, fields, validate, validates, validates_schema

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid_common.api.schemas.nin import NinSchema
from eduid_common.api.schemas.password import PasswordSchema
from eduid_common.api.schemas.u2f import (
    U2FBindRequestSchema,
    U2FEnrollResponseSchema,
    U2FSignResponseSchema,
    U2FVerifyRequestSchema,
    U2FVerifyResponseSchema,
)
from eduid_common.api.schemas.validators import validate_email, validate_nin


class CredentialSchema(EduidSchema):
    key = fields.String(required=True)
    credential_type = fields.String(required=True)
    created_ts = fields.String(required=True)
    success_ts = fields.String(required=True)
    used_for_login = fields.Boolean(required=True, default=False)
    verified = fields.Boolean(required=True, default=False)
    description = fields.String(required=False)


class CredentialList(EduidSchema, CSRFResponseMixin):
    credentials = fields.Nested(CredentialSchema, many=True)


class SecurityResponseSchema(FluxStandardAction):
    payload = fields.Nested(CredentialList)


class ChpassCredentialList(EduidSchema, CSRFResponseMixin):
    credentials = fields.Nested(CredentialSchema, many=True)
    next_url = fields.String(required=True)


class ChpassResponseSchema(FluxStandardAction):
    payload = fields.Nested(ChpassCredentialList)


class CsrfSchema(EduidSchema, CSRFRequestMixin):
    pass


class RedirectSchema(EduidSchema, CSRFResponseMixin):
    location = fields.String(required=True)


class RedirectResponseSchema(FluxStandardAction):

    payload = fields.Nested(RedirectSchema, many=False)


class SuggestedPassword(EduidSchema, CSRFResponseMixin):

    suggested_password = fields.String(required=True)


class SuggestedPasswordResponseSchema(FluxStandardAction):

    payload = fields.Nested(SuggestedPassword, many=False)


class ChangePasswordSchema(PasswordSchema):

    csrf_token = fields.String(required=True)
    old_password = fields.String(required=True)
    new_password = fields.String(required=True)

    @validates('new_password')
    def validate_custom_password(self, value, **kwargs):
        # Set a new error message
        try:
            self.validate_password(value)
        except ValidationError:
            raise ValidationError('chpass.weak-pass')


class AccountTerminatedSchema(FluxStandardAction):
    pass


# U2F schemas
class ConvertRegisteredKeys(EduidSchema):
    class U2FRegisteredKey(EduidSchema):
        version = fields.String(required=True)
        keyhandle = fields.String(required=True, data_key='keyHandle')
        app_id = fields.String(required=True, data_key='appId')
        transports = fields.String()

    registered_keys = fields.Nested(U2FRegisteredKey, required=True, default=list(), many=True)


class EnrollU2FTokenResponseSchema(FluxStandardAction):
    class EnrollU2FTokenResponsePayload(U2FEnrollResponseSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(EnrollU2FTokenResponsePayload)


class BindU2FRequestSchema(U2FBindRequestSchema, CSRFRequestMixin):

    description = fields.String(required=False)


class SignWithU2FTokenResponseSchema(FluxStandardAction):
    class SignWithU2FTokenPayload(U2FSignResponseSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(SignWithU2FTokenPayload)


class VerifyWithU2FTokenRequestSchema(U2FVerifyRequestSchema, CSRFRequestMixin):
    pass


class VerifyWithU2FTokenResponseSchema(FluxStandardAction):
    class Payload(U2FVerifyResponseSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(Payload)


class ModifyU2FTokenRequestSchema(EduidSchema, CSRFRequestMixin):

    credential_key = fields.String(required=True)
    description = fields.String(required=True)


class RemoveU2FTokenRequestSchema(EduidSchema, CSRFRequestMixin):

    credential_key = fields.String(required=True)


# webauthn schemas


class WebauthnOptionsResponseSchema(FluxStandardAction):
    class WebauthnOptionsResponsePayload(EduidSchema, CSRFResponseMixin):
        options = fields.String(required=True)

    payload = fields.Nested(WebauthnOptionsResponsePayload)


class WebauthnRegisterBeginSchema(EduidSchema, CSRFRequestMixin):

    authenticator = fields.String(required=True)


class WebauthnRegisterRequestSchema(EduidSchema, CSRFRequestMixin):

    credential_id = fields.String(required=True, data_key="credentialId")
    attestation_object = fields.String(required=True, data_key="attestationObject")
    client_data = fields.String(required=True, data_key="clientDataJSON")
    description = fields.String(required=True)


class RemoveWebauthnTokenRequestSchema(EduidSchema, CSRFRequestMixin):

    credential_key = fields.String(required=True)


class VerifyWithWebauthnTokenRequestSchema(U2FVerifyRequestSchema):
    pass


class VerifyWithWebauthnTokenResponseSchema(FluxStandardAction):
    class Payload(U2FVerifyResponseSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(Payload)


# Reset password schemas
class ResetPasswordEmailSchema(Schema):

    csrf = fields.String(required=True)
    email = fields.String(required=True)

    @validates('email')
    def validate_email_field(self, value, **kwargs):
        # Set a new error message
        try:
            validate_email(value)
        except ValidationError:
            raise ValidationError(_('Invalid email address'))


class ResetPasswordExtraSecuritySchema(Schema):

    csrf = fields.String(required=True)
    phone_number_index = fields.String(required=False)
    no_extra_security = fields.Boolean(required=False, default=False)


class ResetPasswordVerifyPhoneNumberSchema(Schema):

    csrf = fields.String(required=True)
    phone_code = fields.String(required=True, validate=validate.Length(min=1, error=_('Please enter a code')))


class ResetPasswordNewPasswordSchema(PasswordSchema):

    csrf = fields.String(required=True)
    use_generated_password = fields.Boolean(required=False, default=False)
    custom_password = fields.String(required=False)
    repeat_password = fields.String(required=False)

    @validates_schema
    def new_password_validation(self, data, **kwargs):
        if not data.get('use_generated_password', False):
            custom_password = data.get('custom_password', None)
            repeat_password = data.get('repeat_password', None)
            if not custom_password:
                raise ValidationError(_('Please enter a password'), 'custom_password')
            if not repeat_password:
                raise ValidationError(_('Please repeat the password'), 'repeat_password')
            if custom_password != repeat_password:
                raise ValidationError(_('Passwords does not match'), 'repeat_password')

    @validates('custom_password')
    def validate_custom_password(self, value, **kwargs):
        # Set a new error message
        try:
            self.validate_password(value)
        except ValidationError:
            raise ValidationError(_('Please use a stronger password'))


# NIN schemas
class NINRequestSchema(EduidSchema, CSRFRequestMixin):

    nin = fields.String(required=True, validate=validate_nin)


class NINResponseSchema(FluxStandardAction):
    class RemoveNINPayload(EduidSchema, CSRFResponseMixin):
        success = fields.Boolean(required=True)
        message = fields.String(required=False)
        nins = fields.Nested(NinSchema, many=True)

    payload = fields.Nested(RemoveNINPayload)
