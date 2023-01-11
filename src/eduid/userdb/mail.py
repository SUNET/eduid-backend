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

from typing import Any, Dict, List, Type

from pydantic import validator

from eduid.userdb.element import ElementKey, PrimaryElement, PrimaryElementList

__author__ = "ft"


class MailAddress(PrimaryElement):
    email: str

    @validator("email", pre=True)
    def validate_email(cls, v):
        if not isinstance(v, str):
            raise ValueError("must be a string")
        return v.lower()

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key for e-mail addresses in a PrimaryElementList.
        """
        return ElementKey(self.email)

    @classmethod
    def _from_dict_transform(cls: type[MailAddress], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if "csrf" in data:
            del data["csrf"]

        return data


class MailAddressList(PrimaryElementList[MailAddress]):
    """
    Hold a list of MailAddress instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary e-mail address in the list (except if the list is empty).
    """

    @classmethod
    def from_list_of_dicts(cls: type[MailAddressList], items: list[dict[str, Any]]) -> MailAddressList:
        return cls(elements=[MailAddress.from_dict(this) for this in items])


def address_from_dict(data):
    """
    Create a MailAddress instance from a dict.

    :param data: Mail address parameters from database

    :type data: dict
    :rtype: MailAddress
    """
    return MailAddress.from_dict(data)
