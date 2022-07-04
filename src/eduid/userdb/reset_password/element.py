# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Type, Union

from eduid.userdb.element import Element, ElementKey
from eduid.userdb.util import utc_now


class CodeElement(Element):
    """ """

    code: str
    is_verified: bool

    @property
    def key(self) -> ElementKey:
        """Get element key."""
        return ElementKey(self.code)

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

    def is_expired(self, timeout: timedelta) -> bool:
        """
        Check whether the code is expired.

        :param timeout_seconds: the number of seconds a code is valid
        """
        expiry_date = self.created_ts + timeout
        now = utc_now()
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
