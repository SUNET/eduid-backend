__author__ = "lundberg"

from datetime import datetime
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


def make_etag(version: ObjectId) -> str:
    return f'W/"{version}"'


def get_short_hash(entropy: int = 10) -> str:
    return uuid4().hex[:entropy]


def generate_password(length: int = 12) -> str:
    return pwgen(int(length), no_capitalize=True, no_symbols=True)


def serialize_xml_datetime(value: datetime) -> str:
    """
    The attribute value MUST be encoded as a valid xsd:dateTime as specified in Section 3.3.7 of
    XML-Schema (https://www.w3.org/TR/xmlschema11-2/) and MUST include both a date and a time.

    Example of a valid string: '2021-02-19T08:23:42+00:00'. Seconds are allowed to have decimals,
        so this is also valid: '2021-02-19T08:23:42.123456+00:00'
    """
    # When we load a datetime from mongodb, it will have milliseconds and not microseconds
    # so in order to be consistent we truncate microseconds to milliseconds always.
    milliseconds = value.microsecond // 1000
    return datetime.isoformat(value.replace(microsecond=milliseconds * 1000))


def parse_weak_version(version: ObjectId | str) -> ObjectId | str:
    """
    Parse weak version.
    """
    if isinstance(version, ObjectId):
        return version
    return version.lstrip('W/"').rstrip('"')


def uuid4_str() -> str:
    return str(uuid4())
