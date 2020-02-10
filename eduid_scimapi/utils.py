import base64
from typing import AnyStr, Dict, List, Union


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
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    data += b'=' * (len(data) % 4)
    return base64.urlsafe_b64decode(data)


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
