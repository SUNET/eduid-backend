#
# Copyright (c) 2018 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
"""
This module provides a Request class that extends flask.Request
and adds sanitation to user inputs. This sanitation is performed
on the access methods of the data structures that the request uses to
hold data inputs by the user.
For more information on these structures, see werkzeug.datastructures.

To use this request, assign it to the `request_class` attribute
of the Flask application::

    >>> from eduid_common.api.request import Request
    >>> from flask import Flask
    >>> app = Flask('name')
    >>> app.request_class =  Request
"""

from flask import Request as BaseRequest
from flask import abort, current_app
from werkzeug._compat import iteritems, itervalues
from werkzeug.datastructures import EnvironHeaders, ImmutableMultiDict, ImmutableTypeConversionDict
from werkzeug.utils import cached_property

from eduid_common.api.sanitation import SanitationProblem, Sanitizer


class SanitationMixin(Sanitizer):
    """
    Mixin for werkzeug datastructures providing methods to
    sanitize user inputs.
    """

    def sanitize_input(self, untrusted_text, strip_characters=False):
        logger = current_app.logger
        try:
            return super(SanitationMixin, self).sanitize_input(
                untrusted_text, logger, strip_characters=strip_characters
            )
        except SanitationProblem:
            abort(400)


class SanitizedImmutableMultiDict(ImmutableMultiDict, SanitationMixin):  # type: ignore
    """
    See `werkzeug.datastructures.ImmutableMultiDict`.
    This class is an extension that overrides all access methods to
    sanitize the extracted data.
    """

    def __getitem__(self, key):
        """
        Return the first data value for this key;
        raises KeyError if not found.

        :param key: The key to be looked up.
        :raise KeyError: if the key does not exist.
        """
        value = super(SanitizedImmutableMultiDict, self).__getitem__(key)
        return self.sanitize_input(value)

    def getlist(self, key, type=None):
        """
        Return the list of items for a given key. If that key is not in the
        `MultiDict`, the return value will be an empty list.  Just as `get`
        `getlist` accepts a `type` parameter.  All items will be converted
        with the callable defined there.

        :param key: The key to be looked up.
        :param type: A callable that is used to cast the value in the
                     :class:`MultiDict`.  If a :exc:`ValueError` is raised
                     by this callable the value will be removed from the list.
        :return: a :class:`list` of all the values for the key.
        """
        value_list = super(SanitizedImmutableMultiDict, self).getlist(key, type=type)
        return [self.sanitize_input(v) for v in value_list]

    def items(self, multi=False):
        """
        Return an iterator of ``(key, value)`` pairs.

        :param multi: If set to `True` the iterator returned will have a pair
                      for each value of each key.  Otherwise it will only
                      contain pairs for the first value of each key.
        """
        for key, values in iteritems(dict, self):
            values = [self.sanitize_input(v) for v in values]
            if multi:
                for value in values:
                    yield key, value
            else:
                yield key, values[0]

    def lists(self):
        """Return a list of ``(key, values)`` pairs, where values is the list
        of all values associated with the key."""

        for key, values in iteritems(dict, self):
            values = [self.sanitize_input(v) for v in values]
            yield key, values

    def values(self):
        """
        Returns an iterator of the first value on every key's value list.
        """
        for values in itervalues(dict, self):
            yield self.sanitize_input(values[0])

    def listvalues(self):
        """
        Return an iterator of all values associated with a key.  Zipping
        :meth:`keys` and this is the same as calling :meth:`lists`:

        >>> d = MultiDict({"foo": [1, 2, 3]})
        >>> zip(d.keys(), d.listvalues()) == d.lists()
        True
        """
        for values in itervalues(dict, self):
            yield (self.sanitize_input(v) for v in values)

    def to_dict(self, flat=True):
        """Return the contents as regular dict.  If `flat` is `True` the
        returned dict will only have the first item present, if `flat` is
        `False` all values will be returned as lists.

        :param flat: If set to `False` the dict returned will have lists
                     with all the values in it.  Otherwise it will only
                     contain the first value for each key.
        :return: a :class:`dict`
        """
        if flat:
            d = {}
            for k, v in iteritems(self):
                v = self.sanitize_input(v)
                d[k] = v
            return d
        return dict(self.lists())


class SanitizedTypeConversionDict(ImmutableTypeConversionDict, SanitationMixin):  # type: ignore
    """
    See `werkzeug.datastructures.TypeConversionDict`.
    This class is an extension that overrides all access methods to
    sanitize the extracted data.
    """

    def __getitem__(self, key):
        """
        Sanitized __getitem__
        """
        val = ImmutableTypeConversionDict.__getitem__(self, key)
        return self.sanitize_input(val)

    def get(self, key, default=None, type=None):
        """
        Sanitized, type conversion get.
        The value identified by `key` is sanitized, and if `type`
        is provided, the value is cast to it.

        :param key: the key for the value
        :type key: str
        :para default: the default if `key` is absent
        :type default: str
        :param type: The type to cast  the value
        :type type: type

        :rtype: object
        """
        try:
            val = self.sanitize_input(self[key])
            if type is not None:
                val = type(val)
        except (KeyError, ValueError):
            val = default
        return val

    def values(self):
        """
        sanitized values
        """
        return [self.sanitize_input(v) for v in ImmutableTypeConversionDict.values(self)]

    def items(self):
        """
        Sanitized items
        """
        return [(v[0], self.sanitize_input(v[1])) for v in ImmutableTypeConversionDict.items(self)]

    def pop(self, key):
        """
        Sanitized pop

        :param key: the key for the value
        :type key: str
        """
        val = ImmutableTypeConversionDict.pop(key)
        return self.sanitize_input(val)


class SanitizedEnvironHeaders(EnvironHeaders, SanitationMixin):
    """
    Sanitized and read only version of the headersfrom a WSGI environment.
    """

    def __getitem__(self, key, _get_mode=False):
        """
        Sanitized __getitem__

        :param key: the key for the value
        :type key: str
        :param _get_mode: is a no-op for this class as there is no index but
                          used because get() calls it.
        :type _get_mode: bool
        """
        val = EnvironHeaders.__getitem__(self, key, _get_mode=_get_mode)
        return self.sanitize_input(val)

    def __iter__(self):
        """
        Sanitized __iter__
        """
        for val in EnvironHeaders.__iter__(self):
            yield self.sanitize_input(val)


class Request(BaseRequest, SanitationMixin):
    """
    Request objects with sanitized inputs
    """

    parameter_storage_class = SanitizedImmutableMultiDict
    dict_storage_class = SanitizedTypeConversionDict

    @cached_property
    def headers(self):
        """
        The headers from the WSGI environ as immutable and sanitized
        :class:`~eduid_common.api.request.SanitizedEnvironHeaders`.
        """
        return SanitizedEnvironHeaders(self.environ)

    def get_data(self, *args, **kwargs):
        text = super(Request, self).get_data(*args, **kwargs)
        if text:
            text = self.sanitize_input(text)
        if text is None:
            text = ''
        return text
