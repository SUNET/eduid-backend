# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Type, Union

from eduid.userdb.element import Element


class CodeElement(Element):
    """
    """

    code: str
    is_verified: bool

    @property
    def key(self) -> str:
        """Get element key."""
        return self.code

    @classmethod
    def _from_dict_transform(cls: Type[CodeElement], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if 'verified' in data:
            data['is_verified'] = data.pop('verified')

        return data

    def _to_dict_transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        if 'is_verified' in data:
            data['verified'] = data.pop('is_verified')

        data = super()._to_dict_transform(data)

        return data

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
            return cls(created_by=application, code=code_or_element, is_verified=False)
        if isinstance(code_or_element, dict):
            data = code_or_element
            for this in data.keys():
                if this not in [
                    'application',
                    'code',
                    'created_by',
                    'created_ts',
                    'verified',
                    'modified_ts',
                    'modified_by',
                ]:
                    raise ValueError(f'Unknown data {this} for CodeElement.parse from mapping')
            return cls(
                created_by=data.get('created_by', application),
                code=data['code'],
                created_ts=data.get('created_ts', datetime.utcnow()),
                is_verified=data.get('verified', False),
            )
        if isinstance(code_or_element, CodeElement):
            return code_or_element
        raise ValueError(f'Can\'t create CodeElement from input: {code_or_element}')
