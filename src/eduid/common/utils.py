# -*- coding: utf-8 -*-
__author__ = "lundberg"

from eduid.common.rpc.msg_relay import FullPostalAddress
from eduid.userdb.user import TUserSubclass
import logging

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
        base = "{!s}/".format(base)
    return "{!s}{!s}".format(base, path)


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
        _name_index = (int(given_name_marking) // 10) - 1  # ex. "20" -> 1 (second GivenName is real given name)
        try:
            _given_name = user.given_name.split()[_name_index]
            user.display_name = f"{_given_name} {user.surname}"
        except IndexError:
            # At least occasionally, we've seen GivenName 'Jan-Erik Martin' with GivenNameMarking 30
            pass
    logger.info("User names set from official address")
    logger.debug(
        f"{user_postal_address.name} resulted in given_name: {user.given_name}, "
        f"surname: {user.surname} and display_name: {user.display_name}"
    )
    return user
