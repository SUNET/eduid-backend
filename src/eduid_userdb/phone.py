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
# Author : Fredrik Thulin <fredrik@thulin.net>
#
from __future__ import annotations

import copy
from datetime import datetime
from typing import Any, Dict, Optional, Type, Union

from six import string_types

from eduid_userdb.element import PrimaryElement, PrimaryElementList
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'ft'


class PhoneNumber(PrimaryElement):
    """
    :param data: Phone number parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    """

    def __init__(
        self,
        number: Optional[str] = None,
        application: Optional[str] = None,
        verified: bool = False,
        created_ts: Optional[Union[datetime, bool]] = None,
        primary: bool = False,
        data: Optional[Dict[str, Any]] = None,
        raise_on_unknown: bool = True,
        called_directly: bool = True,
    ):
        raise NotImplementedError()

    @classmethod
    def from_dict(
        cls: Type[PhoneNumber], data: Dict[str, Any], raise_on_unknown: bool = True
    ) -> PhoneNumber:
        """
        Construct password credential from a data dict.
        """
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if 'added_timestamp' in data:
            # old userdb-style creation timestamp
            data['created_ts'] = data.pop('added_timestamp')
        if 'created_ts' not in data:
            data['created_ts'] = True

        if 'mobile' in data:
            # old userdb-style entry
            data['number'] = data.pop('mobile')

        # CSRF tokens were accidentally put in the database some time ago
        if 'csrf' in data:
            del data['csrf']

        number = data.pop('number')

        self = super().from_dict(data, raise_on_unknown=raise_on_unknown)

        self.number = number

        return self

    # -----------------------------------------------------------------
    @property
    def key(self):
        """
        Return the element that is used as key for phone numbers in a PrimaryElementList.
        """
        return self.number

    # -----------------------------------------------------------------
    @property
    def number(self):
        """
        This is the phone number.

        :return: phone number.
        :rtype: str | unicode
        """
        return self._data['number']

    @number.setter
    def number(self, value):
        """
        :param value: phone number.
        :type value: str | unicode
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'number': {!r}".format(value))
        self._data['number'] = str(value.lower())

    # -----------------------------------------------------------------
    def to_dict(self, old_userdb_format=False):
        """
        Convert Element to a dict, that can be used to reconstruct the
        Element later.

        :param old_userdb_format: Set to True to get data back in legacy format.
        :type old_userdb_format: bool
        """
        if not old_userdb_format:
            return self._data
        old = copy.copy(self._data)
        # XXX created_ts -> added_timestamp
        if 'created_ts' in old:
            old['added_timestamp'] = old.pop('created_ts')
        if 'number' in old:
            old['mobile'] = old.pop('number')
        return old


class PhoneNumberList(PrimaryElementList):
    """
    Hold a list of PhoneNumber instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary phone number in the list (except if the list is empty).

    :param phones: List of phone number records
    :type phones: [dict | PhoneNumber]
    """

    def __init__(self, phones, raise_on_unknown=True):
        elements = []

        for this in phones:
            if isinstance(this, PhoneNumber):
                phone = this
            else:
                phone = phone_from_dict(this, raise_on_unknown)
            elements.append(phone)

        PrimaryElementList.__init__(self, elements)

    @property
    def primary(self):
        """
        :return: Return the primary PhoneNumber.

        There must always be exactly one primary element in the list, so an
        PrimaryElementViolation is raised in case this assertion does not hold.

        :rtype: PhoneNumber
        """

        return PrimaryElementList.primary.fget(self)

    @primary.setter
    def primary(self, phone):
        """
        Mark phone as the users primary PhoneNumber.

        This is a PhoneNumberList operation since it needs to atomically update more than one
        element in the list. Marking an element as primary will result in some other element
        loosing it's primary status.

        :param phone: the key of the element to set as primary
        :type  phone: str | unicode
        """
        PrimaryElementList.primary.fset(self, phone)


def phone_from_dict(data, raise_on_unknown=True):
    """
    Create a PhoneNumber instance from a dict.

    :param data: Phone number parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: PhoneNumber
    """
    return PhoneNumber.from_dict(data, raise_on_unknown=raise_on_unknown)
