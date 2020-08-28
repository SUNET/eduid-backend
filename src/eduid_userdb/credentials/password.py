# -*- coding: utf-8 -*-
#
# Copyright (c) 2015 NORDUnet A/S
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
# Author : Johan Lundberg <lundberg@nordu.net>
#
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Type

import bson

from eduid_userdb.credentials import Credential

__author__ = 'lundberg'


@dataclass
class _PasswordRequired:
    """
    Required fields for Password
    """

    credential_id: str
    salt: str

    def __post_init__(self):
        # backwards compat
        if isinstance(self.credential_id, bson.ObjectId):
            self.credential_id = str(self.credential_id)


@dataclass
class Password(Credential, _PasswordRequired):
    """
    """

    is_generated: bool = False

    @property
    def key(self) -> str:
        """
        Return the element that is used as key.
        """
        return self.credential_id

    @classmethod
    def _data_in_transforms(cls: Type[Password], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._data_in_transforms(data)

        if 'source' in data:
            data['created_by'] = data.pop('source')

        if 'id' in data:
            data['credential_id'] = data.pop('id')

        return data

    def _data_out_transforms(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """

            if 'credential_id' in data:
                data['id'] = data.pop('credential_id')
        data = super()._data_out_transforms(data)

        return data


def password_from_dict(data: Dict[str, Any], raise_on_unknown: bool = True) -> Password:
    """
    Create a Password instance from a dict.

    :param data: Password parameters from database
    :param raise_on_unknown: Raise UserHasUnknownData if unrecognized data is encountered
                             kept for B/C
    """
    return Password.from_dict(data)
