import logging
import re
from enum import unique
from typing import Optional

from eduid.webapp.common.api.messages import TranslatableMsg

logger = logging.getLogger(__name__)


@unique
class PDataMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    # successfully saved personal data
    save_success = "pd.save-success"
    # validation error: missing required field
    required = "pdata.field_required"
    # display name must be made up of given name and surname
    display_name_invalid = "pdata.display_name_invalid"
    # validation error: illegal characters
    special_chars = "only allow letters"


def unique_name_parts(name: str) -> list[str]:
    """
    collect all parts of given name and surname as both separate and hyphen separated strings
    "Lars Johan Mats-Ove" -> ['Lars', 'Johan', 'Mats-Ove', 'Mats', 'Ove']
    """
    name_parts = re.split(r" ", name)
    name_parts.extend(re.split(r"[ -]", name))
    return list(set(name_parts))


def is_valid_display_name(
    given_name: Optional[str] = None, surname: Optional[str] = None, display_name: Optional[str] = None
) -> bool:
    """
    Validate the display name is made up of a combination of given_name and surname.
    """
    if not display_name:
        return False

    given_name_parts = []
    surname_parts = []
    display_name_parts = display_name.lower().split()

    if given_name:
        given_name_parts = unique_name_parts(name=given_name.lower())
    if surname:
        surname_parts = unique_name_parts(name=surname.lower())

    # check that at least one given name and one surname is in the display name if set
    if given_name and not [part for part in given_name_parts if part in display_name_parts]:
        return False
    if surname and not [part for part in surname_parts if part in display_name_parts]:
        return False

    # check that all parts of display name are in given name and surname
    parts = given_name_parts + surname_parts
    for part in parts:
        if part in display_name_parts:
            display_name_parts.remove(part)

    if not display_name_parts:
        # all parts of display name are in given name and surname
        return True

    logger.error("Display name is not made up of given name and surname")
    logger.debug(f"Allowed parts: {parts}")
    logger.debug(f"Extra characters in display name: {display_name_parts}")
    return False
