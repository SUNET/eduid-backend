# -*- coding: utf-8 -*-

import re
from marshmallow import ValidationError

__author__ = 'lundberg'

nin_re = re.compile(r'^(18|19|20)\d{2}(0[1-9]|1[0-2])\d{2}\d{4}$')


def validate_nin(nin):
    """
    :param nin: National Identity Number
    :type nin:  str|unicode
    :return: True|ValidationError
    :rtype: Boolean|ValidationError
    """
    if nin_re.match(nin):
        return True
    raise ValidationError('nin needs to be formatted as 18|19|20yymmddxxxx')
