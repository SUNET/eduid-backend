# -*- coding: utf-8 -*-

import copy
from six import string_types
from datetime import datetime, timedelta
from eduid_userdb.element import Element
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


class CodeElement(Element):

    def __init__(self, application=None, code=None, verified=False, created_ts=None, data=None):

        data_in = copy.copy(data)  # to not modify callers data

        if data_in is None:
            if created_ts is None:
                created_ts = True
            data_in = dict(created_by=application,
                           created_ts=created_ts,
                           code=code,
                           used=verified,
                           )
        code = data_in.pop('code', None)
        verified = data_in.pop('verified', False)
        Element.__init__(self, data_in)
        self.code = code
        self.is_verified = verified

    @property
    def key(self):
        """
        Get element key

        :rtype: six.string_types
        """
        return self.code
    # -----------------------------------------------------------------

    @property
    def code(self):
        """
        Get code

        :rtype: six.string_types
        """
        return self._data['code']

    @code.setter
    def code(self, value):
        """
        Get email code

        :rtype: six.string_types
        """
        self._data['code'] = value
    # -----------------------------------------------------------------

    @property
    def is_verified(self):
        """
        :return: True if the code has been used.
        :rtype: bool
        """
        return self._data['verified']

    @is_verified.setter
    def is_verified(self, value):
        """
        :param value: True if code is used
        :type value: bool
        """
        if not isinstance(value, bool):
            raise UserDBValueError("Invalid 'verified': {!r}".format(value))
        self._data['verified'] = value
    # -----------------------------------------------------------------

    def is_expired(self, timeout_seconds):
        """
        Check whether the code is expired.

        :param timeout_seconds: the number of seconds a code is valid
        :type timeout_seconds: int

        :rtype: bool
        """
        delta = timedelta(seconds=timeout_seconds)
        expiry_date = self.created_ts + delta
        now = datetime.now(tz=self.created_ts.tzinfo)
        return expiry_date < now

    @classmethod
    def parse(cls, code_or_element, application):
        if isinstance(code_or_element, string_types):
            return cls(application=application, code=code_or_element)
        if isinstance(code_or_element, dict):
            return cls(data=code_or_element)
