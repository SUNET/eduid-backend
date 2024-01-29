__author__ = "lundberg"

from uuid import uuid4

from bson import ObjectId
from pwgen import pwgen


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


def make_etag(version: ObjectId):
    return f'W/"{version}"'


def get_short_hash(entropy: int = 10) -> str:
    return uuid4().hex[:entropy]


def generate_password(length: int = 12) -> str:
    return pwgen(int(length), no_capitalize=True, no_symbols=True)
