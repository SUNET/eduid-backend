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

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Mapping, Type, Union

from eduid_userdb.element import Element


@dataclass
class _CodeElementRequired:
    """
    """
    code: str
    is_verified: bool


@dataclass
class CodeElement(Element, _CodeElementRequired):
    """
    """
    name_mapping = {'verified': 'is_verified'}

    @property
    def key(self) -> str:
        """Get element key."""
        return self.code

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
                if this not in ['application', 'code', 'created_by', 'created_ts', 'verified', 'modified_ts', 'modified_by']:
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
