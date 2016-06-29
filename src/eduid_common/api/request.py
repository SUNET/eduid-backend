#
# Copyright (c) 2016 NORDUnet A/S
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
on the methods of the datastructures that the request uses to
hold data inputs by the user.
Since those methods need to know the content_type header sent by
users, the datastructure classes' constructors accept a first
argument with the content type, and in the constructor for the
request, where we have the content type, the datastructure classes
constructors are partially applied with the content type, so then
when the request implements those classes, they already know the
content type.

To use this request, assign it to the `request_class` attribute
of the Flask application::

    >>> from eduid_common.api.request import Request
    >>> from flask import Flask
    >>> app = Flask('name')
    >>> app.request_class =  Request
"""

from bleach import clean
from urllib import unquote, quote
from functools import partial

from werkzeug._compat import iteritems, itervalues
from werkzeug.datastructures import ImmutableMultiDict

from flask import Request as BaseRequest
from flask import abort

# XXX there is a logging module in this package that interferes with th one in the standard library
from logging import logging
logger = logging.getLogger(__name__)


class SanitationMixin(object):
    """
    Mixin for werkzeug datastructures providing methods to
    sanitize user inputs.
    """

    def sanitize_input(self, untrusted_text, strip_characters=False,
                       percent_encoded=False):
        """
        Sanitize user input by escaping or removing potentially
        harmful input using a whitelist-based approach with
        bleach as recommended by OWASP.

        :param untrusted_text User input to sanitize
        :param strip_characters Set to True to remove instead of escaping
                                potentially harmful input.

        :param percent_encoded Set to True if the input should be treated
                               as percent encoded if no content type is
                               already defined.

        :return: Sanitized user input

        :type untrusted_text: str | unicode
        :rtype: str | unicode
        """
        try:
            return self._sanitize_input(untrusted_text,
                                        strip_characters=strip_characters,
                                        percent_encoded=percent_encoded)
        except UnicodeDecodeError:
            logger.warn('A malicious user tried to crash the application '
                        'by sending non-unicode input in a GET request')
            raise abort(400)

    def _sanitize_input(self, untrusted_text, strip_characters=False,
                       percent_encoded=False):

        if untrusted_text is None:
            # If we are given None then there's nothing to clean
            return None

        # Decide on whether or not to use percent encoding:
        # 1. Check if the content type has been explicitly set
        # 2. If set, use percent encoding if requested by the client
        # 3. If the content type has not been explicitly set,
        # 3.1 use percent encoding according to the calling
        #    functions preference or,
        # 3.2 use the default value as set in the function definition.
        if self.content_type is not None:

            if self.content_type == "application/x-www-form-urlencoded":
                use_percent_encoding = True
            else:
                use_percent_encoding = False

        else:
            use_percent_encoding = percent_encoded

        if use_percent_encoding:
            # If the untrusted_text is percent encoded we have to:
            # 1. Decode it so we can process it.
            # 2. Encode it to UTF-8 since bleach assumes this encoding
            # 3. Clean it to remove dangerous characters.
            # 4. Percent encode it before returning it back.

            decoded_text = unquote(untrusted_text)

            if not isinstance(decoded_text, unicode):
                decoded_text_in_utf8 = decoded_text.encode("UTF-8")
            else:
                decoded_text_in_utf8 = decoded_text

            cleaned_text = self._safe_clean(decoded_text_in_utf8, strip_characters)
            percent_encoded_text = quote(cleaned_text)

            if decoded_text_in_utf8 != cleaned_text:
                logger.warn('Some potential harmful characters were '
                            'removed from untrusted user input.')

            return percent_encoded_text

        # If the untrusted_text is not percent encoded we only have to:
        # 1. Encode it to UTF-8 since bleach assumes this encoding
        # 2. Clean it to remove dangerous characters.

        if not isinstance(untrusted_text, unicode):
            text_in_utf8 = untrusted_text.encode("UTF-8")
        else:
            text_in_utf8 = untrusted_text

        cleaned_text = self._safe_clean(text_in_utf8, strip_characters)

        if text_in_utf8 != cleaned_text:
            logger.warn('Some potential harmful characters were '
                        'removed from untrusted user input.')

        return cleaned_text

    def _safe_clean(self, untrusted_text, strip_characters=False):
        """
        Wrapper for the clean function of bleach to be able
        to catch when illegal UTF-8 is processed.

        :param untrusted_text: Text to sanitize
        :param strip_characters: Set to True to remove instead of escaping
        :return: Sanitized text

        :type untrusted_text: str | unicode
        :rtype: str | unicode
        """
        try:
            return clean(untrusted_text, strip=strip_characters)
        except KeyError:
            logger.warn('A malicious user tried to crash the application by '
                        'sending illegal UTF-8 in an URI or other untrusted '
                        'user input.')
            abort(400)


class SanitizedImmutableMultiDict(ImmutableMultiDict, SanitationMixin):
    """
    See `werkzeug.datastructures.ImmutableMultiDict`.
    This class is an extension that overrides all "getter" methods to
    sanitize the extracted data.
    """

    def __init__(self, content_type, mapping=None):
        """
        :param content_type: Set to decide on the use of percent encoding
                             according to the content type.
        :param mapping: the initial value for the :class:`MultiDict`.  Either a
                        regular dict, an iterable of ``(key, value)`` tuples
                        or `None`.
        """
        self.content_type = content_type or None
        super(SanitizedImmutableMultiDict, self).__init__(mapping=mapping)

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


class Request(BaseRequest):
    """
    Request objects with sanitized inputs
    """
    def __init__(self, *args, **kwargs):
        super(Request, self).__init__(*args, **kwargs)
        psc = partial(SanitizedImmutableMultiDict, self.content_type)
        self.parameter_storage_class = psc
