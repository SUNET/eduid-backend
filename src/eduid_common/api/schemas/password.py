# -*- coding: utf-8 -*-

import math

from marshmallow import Schema, ValidationError
from zxcvbn import zxcvbn

__author__ = 'lundberg'


class PasswordSchema(Schema):
    class Meta:
        zxcvbn_terms = None
        min_entropy = None

    def __init__(self, *args, **kwargs):
        self.Meta.zxcvbn_terms = kwargs.pop('zxcvbn_terms', [])
        self.Meta.min_entropy = kwargs.pop('min_entropy')
        super(PasswordSchema, self).__init__(*args, **kwargs)

    def validate_password(self, password, **kwargs):
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
        result = zxcvbn(password, user_inputs=self.Meta.zxcvbn_terms)
        if math.log(result.get('guesses', 1), 2) < self.Meta.min_entropy:
            raise ValidationError('The password complexity is too weak.')
