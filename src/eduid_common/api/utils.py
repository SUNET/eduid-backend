# -*- coding: utf-8 -*-

from uuid import uuid4
import sys

PY3 = sys.version_info[0] == 3

if PY3:  # pragma: no cover
    text_type = str
    from io import StringIO
else:  # pragma: no cover
    text_type = unicode
    from StringIO import StringIO


def get_unique_hash():
    return text_type(uuid4())


def get_short_hash(entropy=10):
    return uuid4().hex[:entropy]
