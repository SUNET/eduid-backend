# -*- coding: utf-8 -*-

import re

nin_re = re.compile(r'^(18|19|20)\d{2}(0[1-9]|1[0-2])\d{2}\d{4}$')
# RFC2822_email, http://www.regular-expressions.info/email.html
email_re = re.compile(
    r"(?i)[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/="
    r"?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\."
    r")+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
)


def is_valid_nin(nin: str) -> bool:
    """
    :param nin: National Identity Number
    :return: True or raises ValueError
    """
    if nin_re.match(nin):
        return True
    raise ValueError('nin needs to be formatted as 18|19|20yymmddxxxx')


def is_valid_email(email, **kwargs):
    """
    :param email: E-mail address
    :return: True or raises ValueError
    """
    if email_re.match(email):
        return True
    raise ValueError('email needs to be formatted according to RFC2822')
