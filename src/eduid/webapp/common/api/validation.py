import math
import re
from collections.abc import Sequence
from typing import Any

from zxcvbn import zxcvbn

nin_re_str = r"^(18|19|20)\d{2}(0[1-9]|1[0-2])\d{2}\d{4}$"  # pydantic uses str
nin_re = re.compile(nin_re_str)
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
    raise ValueError("nin needs to be formatted as 18|19|20yymmddxxxx")


def is_valid_email(email: str, **kwargs: Any):
    """
    :param email: E-mail address
    :return: True or raises ValueError
    """
    if email_re.match(email):
        return True
    raise ValueError("email needs to be formatted according to RFC2822")


def is_valid_password(password: str, user_info: Sequence[str], min_entropy: int, min_score: int = 3) -> bool:
    """
    Checks the complexity of the password - NOT if the password is the right one for a user.

    :param password: Password candidate
    :param user_info: List of strings (name, surname etc.) that zxcvbn will reduce the score for
    :param min_entropy: Minimum Shannon entropy (?) of password to allow
    :param min_score: Minimum zxcvbn 'score' of password to allow

    The requirements for entropy were defined in the KANTARA assessment.
    The requirement for zxcvbn 'score' is SWAMID policy as per 2021.

    :return: True or raises ValueError
    """
    # Remove whitespace
    password = "".join(password.split())

    # Reject blank passwords, since zxcvbn crashes on empty passwords.
    if not password:
        raise ValueError("The password complexity is too weak.")

    # Check password complexity with zxcvbn
    result = zxcvbn(password, user_inputs=user_info)
    _guesses = result.get("guesses", 1)
    _pw_entropy = math.log2(_guesses)
    if _pw_entropy < min_entropy:
        raise ValueError("The password complexity is too weak.")
    # This is the SWAMID requirement for zxcvbn since 2021:
    #   "a score of at least 3 (safely unguessable) as defined by the
    #    zxcvbn password strength definition in February 2017"
    if result.get("score", 0) < min_score:
        raise ValueError("The password complexity is too weak.")

    return True
