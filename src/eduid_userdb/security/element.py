# -*- coding: utf-8 -*-

import copy
from datetime import datetime, timedelta
from eduid_userdb.element import Element

__author__ = 'lundberg'


class CodeElement(Element):

    def __init__(self, application=None, code=None, created_ts=None, data=None):

        data_in = copy.copy(data)  # to not modify callers data

        if data_in is None:
            if created_ts is None:
                created_ts = True
            data_in = dict(created_by=application,
                           created_ts=created_ts,
                           code=code,
                           )
            code = data_in.pop('code', None)
        Element.__init__(self, data_in)
        self.code = code

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

    def is_code_expired(self, timeout):
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
