import re

from marshmallow import ValidationError

from eduid.webapp.common.api.utils import get_user
from eduid.webapp.phone.app import current_phone_app as current_app


def normalize_to_e_164(number: str):
    number = "".join(number.split())  # Remove white space
    if number.startswith("00"):
        raise ValidationError("phone.e164_format")
    if number.startswith("0"):
        country_code = current_app.conf.default_country_code
        number = f"+{country_code}{number[1:]}"
    return number


def validate_phone(number: str):
    validate_format_phone(number)
    validate_swedish_mobile(number)
    validate_unique_phone(number)


def validate_format_phone(number: str):
    if not re.match(r"^\+[1-9]\d{6,20}$", number):
        raise ValidationError("phone.phone_format")


def validate_swedish_mobile(number: str):
    if number.startswith("+467"):
        if not re.match(r"^\+467[02369]\d{7}$", number):
            raise ValidationError("phone.swedish_mobile_format")


def validate_unique_phone(number: str):
    user = get_user()
    if user.phone_numbers.find(number):
        raise ValidationError("phone.phone_duplicated")
