# -*- coding: utf-8 -*-

import copy
from six import string_types
from datetime import datetime, timedelta
from eduid_userdb.element import Element
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


class CodeElement(Element):

    def __init__(self, application=None, code=None, is_used=False, created_ts=None, data=None):

        data_in = copy.copy(data)  # to not modify callers data

        if data_in is None:
            if created_ts is None:
                created_ts = True
            data_in = dict(created_by=application,
                           created_ts=created_ts,
                           code=code,
                           used=is_used,
                           )
        code = data_in.pop('code', None)
        is_used = data_in.pop('is_used', False)
        Element.__init__(self, data_in)
        self.code = code
        self.is_used = is_used

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
    def is_used(self):
        """
        :return: True if the code has been used.
        :rtype: bool
        """
        return self._data['is_used']

    @is_used.setter
    def is_used(self, value):
        """
        :param value: True if code is used
        :type value: bool
        """
        if not isinstance(value, bool):
            raise UserDBValueError("Invalid 'is_used': {!r}".format(value))
        self._data['is_used'] = value
    # -----------------------------------------------------------------

    def is_expired(self, timeout):
        """
        Check whether the code is expired.

        :param timeout: the number of hours a code is valid
        :type timeout: int

        :rtype: bool
        """
        created = self.created_ts
        delta = timedelta(hours=timeout)
        expiry_date = created + delta
        expiry_date = expiry_date.replace(tzinfo=None)
        now = datetime.now()
        return expiry_date < now

    @classmethod
    def parse(cls, code_or_element, application):
        if isinstance(code_or_element, string_types):
            return cls(application=application, code=code_or_element)
        if isinstance(code_or_element, dict):
            return cls(data=code_or_element)
