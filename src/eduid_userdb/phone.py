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
from typing import Any, ClassVar, Dict, Optional

from eduid_userdb.element import PrimaryElement, PrimaryElementList

__author__ = 'ft'


@dataclass
class PhoneNumber(PrimaryElement):
    """
    """

    number: Optional[str] = None

    name_mapping: ClassVar[Dict[str, str]] = {
        'application': 'created_by',
        'added_timestamp': 'created_ts',
        'mobile': 'number',
        'csrf': '',
    }
    old_names: ClassVar[tuple] = ('added_timestamp', 'mobile')

    @property
    def key(self) -> Optional[str]:
        """
        Return the element that is used as key for phone numbers in a PrimaryElementList.
        """
        return self.number


class PhoneNumberList(PrimaryElementList):
    """
    Hold a list of PhoneNumber instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary phone number in the list (except if the list is empty).

    :param phones: List of phone number records
    :type phones: [dict | PhoneNumber]
    """

    def __init__(self, phones):
        elements = []

        for this in phones:
            if isinstance(this, PhoneNumber):
                phone = this
            else:
                phone = phone_from_dict(this)
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


def phone_from_dict(data: Dict[str, Any]) -> PhoneNumber:
    """
    Create a PhoneNumber instance from a dict.

    :param data: Phone number parameters from database
    """
    return PhoneNumber.from_dict(data)
