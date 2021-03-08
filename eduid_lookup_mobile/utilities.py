__author__ = 'mathiashedstrom'

import re

import phonenumbers


def format_NIN(nin):
    if nin is None:
        return

    # Remove all non-digits
    nin = re.sub(r"\D", '', nin)
    return nin


def get_region_from_number(number):
    # TODO default region should be None?
    region = 'SE'
    if number.startswith('+'):
        region = phonenumbers.region_code_for_number(phonenumbers.parse(number, region))
    return region


def format_mobile_number(number, region):
    """
    Format a single or a list of numbers to E164 standard
    :param number: a single number string, or a list of numbers
    :param region: the region of the number/s
    :return:
    """
    if isinstance(number, list):
        formatted_numbers = []
        for one_number in number:
            formatted_numbers.append(_format_number(one_number, region))
        return formatted_numbers

    return _format_number(number, region)


def _format_number(number, region):
    # if no region, just remove all non-digits, but keep + sign
    if region is None:
        if number.startswith("+"):
            return "+{number}".format(number=re.sub(r"\D", '', number))
        return re.sub(r"\D", '', number)
    return phonenumbers.format_number(phonenumbers.parse(number, region), phonenumbers.PhoneNumberFormat.E164)
