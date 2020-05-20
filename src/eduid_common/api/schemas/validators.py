# -*- coding: utf-8 -*-

import re

from marshmallow import ValidationError

__author__ = 'lundberg'

nin_re = re.compile(r'^(18|19|20)\d{2}(0[1-9]|1[0-2])\d{2}\d{4}$')
# RFC2822_email, http://www.regular-expressions.info/email.html
email_re = re.compile(
    r"(?i)[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/="
    r"?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\."
    r")+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
)


def validate_nin(nin, **kwargs):
    """
    :param nin: National Identity Number
    :type nin: string_types
    :return: True|ValidationError
    :rtype: Boolean|ValidationError
    """
    if nin_re.match(nin):
        return True
    raise ValidationError('nin needs to be formatted as 18|19|20yymmddxxxx')


def validate_email(email, **kwargs):
    """
    :param email: E-mail address
    :type email: string_types
    :return: True|ValidationError
    :rtype: Boolean|ValidationError
    """
    if email_re.match(email):
        return True
    raise ValidationError('email needs to be formatted according to RFC2822')
