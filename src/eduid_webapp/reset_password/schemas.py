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

from flask_babel import gettext as _
from marshmallow import fields, Schema, validates, validates_schema, validate, ValidationError

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFResponseMixin, CSRFRequestMixin
from eduid_common.api.schemas.validators import validate_email

__author__ = 'eperez'


class ResetPasswordInitSchema(Schema):

    email = fields.String(required=True)

    @validates('email')
    def validate_email_field(self, value):
        # Set a new error message
        try:
            validate_email(value)
        except ValidationError:
            raise ValidationError(_('Invalid email address'))


class ResetPasswordEmailCodeSchema(Schema):

    code = fields.String(required=True)


class ResetPasswordWithCodeSchema(CSRFRequestMixin):
    # XXX this class should be merged with the other schemas dealing with
    # passwords
    
    code = fields.String(required=True)
    use_generated_password = fields.Boolean(required=False, default=False)
    custom_password = fields.String(required=False)
    repeat_password = fields.String(required=False)

    @validates_schema
    def new_password_validation(self, data):
        if not data.get('use_generated_password', False):
            custom_password = data.get('custom_password', None)
            repeat_password = data.get('repeat_password', None)
            if not custom_password:
                raise ValidationError(_('Please enter a password'), ['custom_password'])
            if not repeat_password:
                raise ValidationError(_('Please repeat the password'), ['repeat_password'])
            if custom_password != repeat_password:
                raise ValidationError(_('Passwords does not match'), ['repeat_password'])

    @validates('custom_password')
    def validate_custom_password(self, value):
        # Set a new error message
        try:
            self.validate_password(value)
        except ValidationError:
            raise ValidationError(_('Please use a stronger password'))

    def validate_password(self, password):
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
        from eduid_webapp.security.app import current_security_app
        min_entropy = current_security_app.config.min_entropy
        result = zxcvbn(password)
        if math.log(result.get('guesses', 1), 2) < min_entropy:
            raise ValidationError('The password complexity is too weak.')
