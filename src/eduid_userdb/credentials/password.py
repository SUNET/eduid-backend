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
from __future__ import absolute_import

import copy
from typing import Any, Dict, Optional, Type, Union

from bson.objectid import ObjectId

from eduid_userdb.credentials import Credential
from eduid_userdb.element import TElementSubclass
from eduid_userdb.exceptions import UserDBValueError, UserHasUnknownData

__author__ = 'lundberg'


class Password(Credential):
    def __init__(
        self,
        credential_id: Optional[ObjectId] = None,
        salt: Optional[str] = None,
        is_generated: bool = False,
        application: Optional[str] = None,
        created_ts: Optional[Union[str, bool]] = None,
        data: Optional[dict] = None,
        raise_on_unknown: bool = True,
        called_directly: bool = True,
    ):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                id=credential_id, salt=salt, is_generated=is_generated, created_by=application, created_ts=created_ts,
            )

        if 'source' in data:  # TODO: Load and save all users in the database to replace source with created_by
            data['created_by'] = data.pop('source')
        Credential.__init__(self, data, called_directly=called_directly)
        if 'id' in data:  # TODO: Load and save all users in the database to replace id with credential_id
            data['credential_id'] = data.pop('id')
        self.is_generated = data.pop('is_generated', False)
        self.credential_id = data.pop('credential_id')
        self.salt = data.pop('salt')

        leftovers = data.keys()
        if leftovers:
            if raise_on_unknown:
                raise UserHasUnknownData('Password {!r} unknown data: {!r}'.format(self.key, leftovers))
            # Just keep everything that is left as-is
            self._data.update(data)

    @classmethod
    def from_dict(cls: Type[TElementSubclass], data: Dict[str, Any], raise_on_unknown: bool = True) -> TElementSubclass:
        """
        Construct user from a data dict.
        """
        return cls(data=data, raise_on_unknown=raise_on_unknown, called_directly=False)

    @property
    def key(self) -> str:
        """
        Return the element that is used as key.
        """
        return self.credential_id

    @property
    def credential_id(self) -> str:
        """
        This is a reference to the ObjectId in the authentication private database.
        """
        return self._data['credential_id']

    @credential_id.setter
    def credential_id(self, value: Union[ObjectId, str]):
        """
        :param value: Reference to the password credential in the authn backend db.
        """
        if isinstance(value, ObjectId):
            # backwards compatibility
            value = str(value)
        if not isinstance(value, str):
            raise UserDBValueError("Invalid 'credential_id': {!r}".format(value))
        self._data['credential_id'] = value

    @property
    def salt(self) -> str:
        """
        Password salt.
        """
        return self._data['salt']

    @salt.setter
    def salt(self, value: str):
        """
        :param value: Password salt.
        """
        if not isinstance(value, str):
            raise UserDBValueError(f"Invalid 'salt': {value}")
        self._data['salt'] = value

    @property
    def is_generated(self) -> bool:
        """
        Whether the password was generated or custom
        """
        return self._data['is_generated']

    @is_generated.setter
    def is_generated(self, value: bool):
        """
        :param value: Whether the password was generated
        """
        if not isinstance(value, bool):
            raise UserDBValueError(f"Invalid 'is_generated': {value}")
        self._data['is_generated'] = value


def password_from_dict(data, raise_on_unknown=True):
    """
    Create a Password instance from a dict.

    :param data: Password parameters from database
    :param raise_on_unknown: Raise UserHasUnknownData if unrecognized data is encountered

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: Password
    """
    return Password.from_dict(data, raise_on_unknown=raise_on_unknown)
