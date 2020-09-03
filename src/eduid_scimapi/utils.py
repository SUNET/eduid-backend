import base64
from typing import AnyStr, Dict, List, Union
from uuid import uuid4

from bson import ObjectId


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
    path = path.lstrip('/')
    if not base.endswith('/'):
        base = '{!s}/'.format(base)
    return '{!s}{!s}'.format(base, path)


def b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('utf-8').strip('=')


def b64_decode(data: AnyStr) -> bytes:
    if isinstance(data, str):
        _data = data.encode('utf-8')
    elif isinstance(data, bytes):
        _data = data
    else:
        raise ValueError('b64_decode needs either str or bytes')
    _data += b'=' * (len(_data) % 4)
    return base64.urlsafe_b64decode(_data)


def filter_none(x: Union[Dict, List]) -> Union[Dict, List]:
    """
    Recursively removes key, value pairs or items that is None.
    """
    if isinstance(x, dict):
        return {k: filter_none(v) for k, v in x.items() if v is not None}
    elif isinstance(x, list):
        return [filter_none(i) for i in x if x is not None]
    else:
        return x


def make_etag(version: ObjectId):
    return f'W/"{version}"'


def get_unique_hash():
    return str(uuid4())


def get_short_hash(entropy=10):
    return uuid4().hex[:entropy]
