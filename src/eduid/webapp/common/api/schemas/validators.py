from typing import Any

from marshmallow import ValidationError

from eduid.webapp.common.api.validation import is_valid_email, is_valid_nin

__author__ = "lundberg"


def validate_nin(nin: str, **kwargs: Any) -> bool:
    """
    :param nin: National Identity Number
    :type nin: string_types
    :return: True|ValidationError
    :rtype: Boolean|ValidationError
    """
    try:
        return is_valid_nin(nin)
    except ValueError:
        raise ValidationError("nin needs to be formatted as 18|19|20yymmddxxxx")


def validate_email(email: str, **kwargs: Any) -> bool:
    """
    :param email: E-mail address
    :type email: string_types
    :return: True|ValidationError
    :rtype: Boolean|ValidationError
    """
    try:
        return is_valid_email(email)
    except ValueError:
        raise ValidationError("email needs to be formatted according to RFC2822")
