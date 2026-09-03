import logging

from eduid.common.rpc.msg_relay import Name
from eduid.userdb.logs.element import NinNavetProofingLogElement
from eduid.userdb.user import User

__author__ = "lundberg"

logger = logging.getLogger(__name__)


def get_marked_given_name(given_name: str, given_name_marking: str | None) -> str:
    """
    Given name marking denotes up to two given names, and is used to determine
    which of the given names are to be primarily used in addressing a person.
    For this purpose, the given_name_marking is two numbers:
        indexing starting at 1
        the second can be 0 for only one mark
        hyphenated names are counted separately (i.e. Jan-Erik are two separate names)
            If they are both marked they should be re-hyphenated
        ex. given_name: Sven Jan-Erik, given_name_marking: 23 -> Jan-Erik
            given_name: Lisa Moa, given_name_marking: 20 -> Moa

    current version of documentation:
    Allmän beskrivning av Navet (version 4.1)
    https://www.skatteverket.se/download/18.49df84321939117d78ae/1742454508179/Navet-Allman-beskrivning.pdf

    :param given_name: Given name
    :param given_name_marking: Given name marking

    :return: Marked given name (Tilltalsnamn)
    """
    if not given_name_marking or given_name_marking == "00":
        return given_name

    # cheating with indexing
    _given_names: list[str | None] = [None]
    for name in given_name.split():
        if "-" in name:
            # hyphenated names are counted separately
            _given_names.extend(name.split("-"))
        else:
            _given_names.append(name)

    _optional_marked_names: list[str | None] = [_given_names[int(i)] for i in given_name_marking]
    # remove None values
    # i.e. 0 index and hyphenated names second part placeholder
    _marked_names: list[str] = [name for name in _optional_marked_names if name is not None]
    if "-".join(_marked_names) in given_name:
        return "-".join(_marked_names)
    else:
        return " ".join(_marked_names)


def get_official_surname(name: Name) -> str | None:
    """
    The surname eduID stores for a person is Navet's surname with any middle name (mellannamn)
    prepended, as a middle name is legally part of a person's surname.
    https://www4.skatteverket.se/rattsligvagledning/edition/2026.12/330287.html

    Use this - never Name.surname directly - when comparing a stored user.surname to Navet data.

    :param name: Name as reported by Navet

    :return: The official surname, or None if Navet reported no usable surname
    """
    parts = [part.strip() for part in (name.middle_name, name.surname) if part and part.strip()]
    if not parts:
        return None
    return " ".join(parts)


def set_user_names_from_official_address[T: User](user: T, proofing_log_entry: NinNavetProofingLogElement) -> T:
    """
    :param user: Proofing app private userdb user
    :param proofing_log_entry: Proofing log entry element

    :returns: User object
    """
    official_name = proofing_log_entry.user_postal_address.name
    user.given_name = official_name.given_name
    # a middle name (mellannamn) is part of the surname
    user.surname = get_official_surname(official_name)

    # please mypy, and guard against blank names from Navet
    if not user.given_name or not user.surname:
        raise RuntimeError("No given name or surname found in proofing log user postal address")

    # Set chosen given name with given name marking if present
    if official_name.given_name_marking:
        user.chosen_given_name = get_marked_given_name(user.given_name, official_name.given_name_marking)

    user.legal_name = f"{user.given_name} {user.surname}"

    logger.info("User names set from official address")
    logger.debug(
        f"{official_name} resulted in given_name: {user.given_name}, "
        f"chosen_given_name: {user.chosen_given_name}, surname: {user.surname} and legal_name: {user.legal_name}"
    )
    return user
