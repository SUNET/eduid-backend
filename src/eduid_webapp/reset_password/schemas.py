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
import math

import zxcvbn
from flask_babel import gettext as _
from marshmallow import fields, Schema, validates, validates_schema, validate, ValidationError

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFResponseMixin, CSRFRequestMixin
from eduid_common.api.schemas.validators import validate_email
from eduid_webapp.security.schemas import CredentialSchema

__author__ = 'eperez'


class ResetPasswordInitSchema(CSRFRequestMixin):

    email = fields.String(required=True)

    @validates('email')
    def validate_email_field(self, value):
        # Set a new error message
        try:
            validate_email(value)
        except ValidationError:
            raise ValidationError(_('Invalid email address'))


class ResetPasswordEmailCodeSchema(CSRFRequestMixin):

    code = fields.String(required=True)


class ResetPasswordExtraSecSchema(CSRFRequestMixin):

    code = fields.String(required=True)
    phone_index = fields.Integer(required=True)


class ResetPasswordWithCodeSchema(CSRFRequestMixin):
    
    code = fields.String(required=True)
    password = fields.String(required=True)

    @validates('password')
    def validate_password(self, value):
        # Set a new error message
        try:
            self._validate_password(value)
        except ValidationError:
            raise ValidationError(_('Please use a stronger password'))

    def _validate_password(self, password):
        """
        :param password: New password
        :type password: string_types

        :return: True|ValidationError
        :rtype: Boolean|ValidationError

        Checks the complexity of the password
        """
        # Remove whitespace
        password = ''.join(password.split())

        # Reject blank passwords
        if not password:
            raise ValidationError('The password complexity is too weak.')

        # Check password complexity with zxcvbn
        from eduid_webapp.reset_password.app import current_reset_password_app
        min_entropy = current_reset_password_app.config.password_entropy
        result = zxcvbn.zxcvbn(password)
        if math.log(result.get('guesses', 1), 2) < min_entropy:
            raise ValidationError('The password complexity is too weak.')


class ResetPasswordWithPhoneCodeSchema(ResetPasswordWithCodeSchema):
    phone_code = fields.String(required=True)


class ChpassCredentialList(EduidSchema, CSRFResponseMixin):
    credentials = fields.Nested(CredentialSchema, many=True)
    next_url = fields.String(required=True)


class ChpassResponseSchema(FluxStandardAction):
    payload = fields.Nested(ChpassCredentialList)


class ChangePasswordSchema(EduidSchema, CSRFRequestMixin):

    old_password = fields.String(required=True)
    new_password = fields.String(required=True)


class SuggestedPassword(EduidSchema, CSRFResponseMixin):

    suggested_password = fields.String(required=True)


class SuggestedPasswordResponseSchema(FluxStandardAction):

    payload = SuggestedPassword()
