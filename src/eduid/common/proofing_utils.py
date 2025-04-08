import logging

from eduid.userdb.logs.element import TNinNavetProofingLogElementSubclass
from eduid.userdb.user import TUserSubclass

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

    current version of documentation:
    https://www.skatteverket.se/download/18.2cf1b5cd163796a5c8bf20e/1530691773712/AllmanBeskrivning.pdf

    :param given_name: Given name
    :param given_name_marking: Given name marking

    :return: Marked given name (Tilltalsnamn)
    """
    if not given_name_marking or "00" == given_name_marking:
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


def set_user_names_from_official_address(
    user: TUserSubclass, proofing_log_entry: TNinNavetProofingLogElementSubclass
) -> TUserSubclass:
    """
    :param user: Proofing app private userdb user
    :param proofing_log_entry: Proofing log entry element

    :returns: User object
    """
    user.given_name = proofing_log_entry.user_postal_address.name.given_name
    user.surname = proofing_log_entry.user_postal_address.name.surname
    user.legal_name = (
        f"{proofing_log_entry.user_postal_address.name.given_name} "
        f"{proofing_log_entry.user_postal_address.name.surname}"
    )

    # please mypy
    if user.given_name is None or user.surname is None:
        raise RuntimeError("No given name or surname found in proofing log user postal address")

    # Set chosen given name with given name marking if present
    given_name_marking = proofing_log_entry.user_postal_address.name.given_name_marking
    if given_name_marking:
        _given_name = get_marked_given_name(user.given_name, given_name_marking)
        user.chosen_given_name = _given_name
    logger.info("User names set from official address")
    logger.debug(
        f"{proofing_log_entry.user_postal_address.name} resulted in given_name: {user.given_name}, "
        f"chosen_given_name: {user.chosen_given_name}, surname: {user.surname} and legal_name: {user.legal_name}"
    )
    return user
