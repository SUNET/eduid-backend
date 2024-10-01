import logging
import re
from enum import unique

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
    chosen_given_name_invalid = "pdata.chosen_given_name_invalid"
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


def is_valid_chosen_given_name(given_name: str | None = None, chosen_given_name: str | None = None) -> bool:
    """
    Validate the chosen given name is made up of a combination of given_name.
    """
    if not chosen_given_name:
        return False

    given_name_parts = []
    chosen_given_name_parts = chosen_given_name.lower().split()

    if given_name:
        given_name_parts = unique_name_parts(name=given_name.lower())

    # check that at least one given name is in the chosen given name if set
    if given_name and not [part for part in given_name_parts if part in chosen_given_name_parts]:
        return False

    # check that all parts of chosen given name are in given name
    for part in given_name_parts:
        if part in chosen_given_name_parts:
            chosen_given_name_parts.remove(part)

    if not chosen_given_name_parts:
        # all parts of chosen given name are in given name
        return True

    logger.error("Display name is not made up of given name and surname")
    logger.debug(f"Allowed parts: {given_name_parts}")
    logger.debug(f"Extra characters in display name: {chosen_given_name_parts}")
    return False
