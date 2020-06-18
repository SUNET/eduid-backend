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

import copy
from datetime import datetime
from typing import Any, Dict, Optional, Union

from six import string_types

from eduid_userdb.element import PrimaryElement, PrimaryElementList
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'ft'


class MailAddress(PrimaryElement):
    """
    :param data: Mail address parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    """

    def __init__(
        self,
        email: Optional[str] = None,
        application: Optional[str] = None,
        verified: bool = False,
        created_ts: Optional[Union[datetime, bool]] = None,
        primary: bool = False,
        data: Optional[Dict[str, Any]] = None,
        raise_on_unknown: bool = True,
        called_directly: bool = True,
    ):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(email=email, created_by=application, created_ts=created_ts, verified=verified, primary=primary,)
        if 'added_timestamp' in data:
            # old userdb-style creation timestamp
            data['created_ts'] = data.pop('added_timestamp')
        # CSRF tokens were accidentally put in the database some time ago
        if 'csrf' in data:
            del data['csrf']
        PrimaryElement.__init__(self, data, raise_on_unknown, called_directly=called_directly, ignore_data=['email'])
        self.email = data.pop('email')

    # -----------------------------------------------------------------
    @property
    def key(self):
        """
        Return the element that is used as key for e-mail addresses in a PrimaryElementList.
        """
        return self.email

    # -----------------------------------------------------------------
    @property
    def email(self):
        """
        This is the e-mail address.

        :return: E-mail address.
        :rtype: str
        """
        return self._data['email']

    @email.setter
    def email(self, value):
        """
        :param value: e-mail address.
        :type value: str | unicode
        """
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'email': {!r}".format(value))
        self._data['email'] = str(value.lower())

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
        del old['primary']
        return old


class MailAddressList(PrimaryElementList):
    """
    Hold a list of MailAddress instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary e-mail address in the list (except if the list is empty).

    :param addresses: List of e-mail addresses
    :type addresses: [dict | MailAddress]
    """

    def __init__(self, addresses, raise_on_unknown=True):
        elements = []

        for this in addresses:
            if isinstance(this, MailAddress):
                address = this
            else:
                address = address_from_dict(this, raise_on_unknown)
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


def address_from_dict(data, raise_on_unknown=True):
    """
    Create a MailAddress instance from a dict.

    :param data: Mail address parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: MailAddress
    """
    return MailAddress.from_dict(data, raise_on_unknown=raise_on_unknown)
