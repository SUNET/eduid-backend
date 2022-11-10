__author__ = "mathiashedstrom"

import re
from typing import List, Optional, Sequence

import phonenumbers


def format_NIN(nin: Optional[str]) -> Optional[str]:
    if nin is None:
        return None

    # Remove all non-digits
    nin = re.sub(r"\D", "", nin)
    return nin


def format_mobile_number(numbers: Sequence[str], region: Optional[str]) -> List[str]:
    """
    Format a list of numbers to E.164 standard
    :param numbers: a list of phone numbers
    :param region: the region of the number/s - e.g. 'SE'
    :return: A list of E.164 formatted phone numbers
    """
    return [_format_number(x, region) for x in numbers]


def _format_number(number: str, region: Optional[str]):
    """Parse a number and reconstruct it to the canonical E.164 format"""
    return phonenumbers.format_number(phonenumbers.parse(number, region), phonenumbers.PhoneNumberFormat.E164)
