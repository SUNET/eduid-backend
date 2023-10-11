__author__ = "lundberg"

import logging
from typing import List, Optional

from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.userdb.user import TUserSubclass

logger = logging.getLogger(__name__)


def urlappend(base: str, path: str) -> str:
    """
    :param base: Base url
    :param path: Path to join to base
    :return: Joined url

    Used instead of urlparse.urljoin to append path to base in an obvious way.

    >>> urlappend('https://test.com/base-path', 'my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path/', 'my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path/', '/my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path', '/my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path', '/my-path/')
    'https://test.com/base-path/my-path/'
    """
    path = path.lstrip("/")
    if not base.endswith("/"):
        base = f"{base!s}/"
    return f"{base!s}{path!s}"


# TODO: removeprefix and removesuffix be a part of str in python 3.9
def removeprefix(s: str, prefix: str) -> str:
    if s.startswith(prefix):
        return s[len(prefix) :]
    else:
        return s[:]


def removesuffix(s: str, suffix: str) -> str:
    # suffix='' should not call self[:-0].
    if suffix and s.endswith(suffix):
        return s[: -len(suffix)]
    else:
        return s[:]


def get_marked_given_name(given_name: str, given_name_marking: Optional[str]) -> str:
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
    _given_names: List[Optional[str]] = [None]
    for name in given_name.split():
        if "-" in name:
            # hyphenated names are counted separately
            _given_names.extend(name.split("-"))
        else:
            _given_names.append(name)

    _optional_marked_names: List[Optional[str]] = []
    for i in given_name_marking:
        _optional_marked_names.append(_given_names[int(i)])
    # remove None values
    # i.e. 0 index and hyphenated names second part placeholder
    _marked_names: List[str] = [name for name in _optional_marked_names if name is not None]
    if "-".join(_marked_names) in given_name:
        return "-".join(_marked_names)
    else:
        return " ".join(_marked_names)


def set_user_names_from_official_address(user: TUserSubclass, user_postal_address: FullPostalAddress) -> TUserSubclass:
    """
    :param user: Proofing app private userdb user
    :param user_postal_address: user postal address

    :returns: User object
    """
    user.given_name = user_postal_address.name.given_name
    user.surname = user_postal_address.name.surname
    if user.given_name is None or user.surname is None:
        # please mypy
        raise RuntimeError("No given name or surname found in proofing log user postal address")
    given_name_marking = user_postal_address.name.given_name_marking
    user.display_name = f"{user.given_name} {user.surname}"
    if given_name_marking:
        _given_name = get_marked_given_name(user.given_name, given_name_marking)
        user.display_name = f"{_given_name} {user.surname}"
    logger.info("User names set from official address")
    logger.debug(
        f"{user_postal_address.name} resulted in given_name: {user.given_name}, "
        f"surname: {user.surname} and display_name: {user.display_name}"
    )
    return user
