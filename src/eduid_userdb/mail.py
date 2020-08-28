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

from dataclasses import dataclass
from typing import Any, Dict, Optional, Type

from eduid_userdb.element import PrimaryElement, PrimaryElementList

__author__ = 'ft'


@dataclass
class MailAddress(PrimaryElement):
    """
    """

    email: Optional[str] = None

    @property
    def key(self) -> Optional[str]:
        """
        Return the element that is used as key for e-mail addresses in a PrimaryElementList.
        """
        return self.email

    @classmethod
    def _data_in_transforms(cls: Type[MailAddress], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._data_in_transforms(data)

        if 'added_timestamp' in data:
            data['created_ts'] = data.pop('added_timestamp')

        if 'csrf' in data:
            del data['csrf']

        return data

    def _data_out_transforms(self, data: Dict[str, Any], old_userdb_format: bool = False) -> Dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        if old_userdb_format:
            if 'created_ts' in data:
                data['added_timestamp'] = data.pop('created_ts')

        data = super()._data_out_transforms(data, old_userdb_format)

        return data


class MailAddressList(PrimaryElementList):
    """
    Hold a list of MailAddress instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary e-mail address in the list (except if the list is empty).

    :param addresses: List of e-mail addresses
    :type addresses: [dict | MailAddress]
    """

    def __init__(self, addresses):
        elements = []

        for this in addresses:
            if isinstance(this, MailAddress):
                address = this
            else:
                address = address_from_dict(this)
            elements.append(address)

        PrimaryElementList.__init__(self, elements)

    @property
    def primary(self):
        """
        :return: Return the primary MailAddress.

        There must always be exactly one primary element in the list, so an
        PrimaryElementViolation is raised in case this assertion does not hold.

        :rtype: MailAddress
        """
        return PrimaryElementList.primary.fget(self)

    @primary.setter
    def primary(self, email):
        """
        Mark email as the users primary MailAddress.

        This is a MailAddressList operation since it needs to atomically update more than one
        element in the list. Marking an element as primary will result in some other element
        loosing it's primary status.

        :param email: the key of the element to set as primary
        :type  email: str | unicode
        """
        PrimaryElementList.primary.fset(self, email)

    def find(self, email):
        """
        Find an MailAddress from the element list, using the key.

        :param email: the e-mail address to look for in the list of elements
        :type email: str | unicode
        :return: MailAddress instance if found, or False if none was found
        :rtype: MailAddress | False
        """
        # implemented here to get proper type information
        return PrimaryElementList.find(self, email)


def address_from_dict(data):
    """
    Create a MailAddress instance from a dict.

    :param data: Mail address parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: MailAddress
    """
    return MailAddress.from_dict(data)
