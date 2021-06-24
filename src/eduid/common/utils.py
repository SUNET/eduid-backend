# -*- coding: utf-8 -*-
__author__ = 'lundberg'


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
