# -*- coding: utf-8 -*-
from __future__ import annotations

import copy
from datetime import datetime, timedelta
from typing import Dict, Mapping, Optional, Type, Union

from six import string_types

from eduid_userdb.element import Element
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


class CodeElement(Element):

    def __init__(self, application: str, code: str, verified: bool = False,
                 created_ts: Optional[Union[datetime, bool]] = None, data: Optional[Mapping] = None):

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
    def key(self) -> str:
        """Get element key"""
        return self.code
    # -----------------------------------------------------------------

    @property
    def code(self) -> str:
        """Get code"""
        return self._data['code']

    @code.setter
    def code(self, value: str):
        """Get email code"""
        self._data['code'] = value
    # -----------------------------------------------------------------

    @property
    def is_verified(self) -> bool:
        """True if the code has been used."""
        return self._data['verified']

    @is_verified.setter
    def is_verified(self, value: bool):
        """
        :param value: True if code is used
        """
        if not isinstance(value, bool):
            raise UserDBValueError("Invalid 'verified': {!r}".format(value))
        self._data['verified'] = value
    # -----------------------------------------------------------------

    def is_expired(self, timeout_seconds: int) -> bool:
        """
        Check whether the code is expired.

        :param timeout_seconds: the number of seconds a code is valid
        """
        delta = timedelta(seconds=timeout_seconds)
        expiry_date = self.created_ts + delta
        now = datetime.now(tz=self.created_ts.tzinfo)
        return expiry_date < now

    @classmethod
    def parse(cls: Type[CodeElement], code_or_element: Union[Dict, CodeElement, str], application: str) -> CodeElement:
        if isinstance(code_or_element, string_types):
            return cls(application=application, code=code_or_element)
        if isinstance(code_or_element, dict):
            return cls(data=code_or_element)
        if isinstance(code_or_element, CodeElement):
            return code_or_element
        raise ValueError(f'Can\'t create CodeElement from input: {code_or_element}')

