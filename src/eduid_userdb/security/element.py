# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Mapping, Type, Union

from eduid_userdb.deprecation import deprecated
from eduid_userdb.element import Element
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


# @deprecated("Remove once the password reset views are served from their own webapp")
class CodeElement(Element):
    @deprecated("Remove once the password reset views are served from their own webapp")
    def __init__(self, application: str, code: str, verified: bool, created_ts: Union[datetime, bool]):

        data = dict(created_by=application, created_ts=created_ts,)
        super().__init__(data, called_directly=False)

        self.code = code
        self.is_verified = verified

    @property
    def key(self) -> str:
        """Get element key."""
        return self.code

    # -----------------------------------------------------------------

    @property
    def code(self) -> str:
        """Get email code."""
        return self._data['code']

    @code.setter
    def code(self, value: str):
        self._data['code'] = value

    # -----------------------------------------------------------------

    @property
    def is_verified(self) -> bool:
        """Return True if the code has been used."""
        return self._data['verified']

    @is_verified.setter
    def is_verified(self, value: bool):
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
    def parse(
        cls: Type[CodeElement], code_or_element: Union[Mapping, CodeElement, str], application: str
    ) -> CodeElement:
        if isinstance(code_or_element, str):
            return cls(application=application, code=code_or_element, created_ts=True, verified=False)
        if isinstance(code_or_element, dict):
            data = code_or_element
            for this in data.keys():
                if this not in ['application', 'code', 'created_by', 'created_ts', 'verified']:
                    raise ValueError(f'Unknown data {this} for CodeElement.parse from mapping')
            return cls(
                application=data.get('created_by', application),
                code=data['code'],
                created_ts=data.get('created_ts', True),
                verified=data.get('verified', False),
            )
        if isinstance(code_or_element, CodeElement):
            return code_or_element
        raise ValueError(f'Can\'t create CodeElement from input: {code_or_element}')
