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

from six import string_types

from eduid_userdb.element import PrimaryElement, PrimaryElementList
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'ft'


class Nin(PrimaryElement):
    """
    :param data: Phone number parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    """

    def __init__(
        self,
        number=None,
        application=None,
        verified=False,
        created_ts=None,
        primary=None,
        data=None,
        raise_on_unknown=True,
        called_directly=True,
    ):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(
                number=number, created_by=application, created_ts=created_ts, verified=verified, primary=primary,
            )

        PrimaryElement.__init__(self, data, raise_on_unknown, called_directly=called_directly, ignore_data=['number'])
        self.number = data.pop('number')

    # -----------------------------------------------------------------
    @property
    def key(self):
        """
        Return the element that is used as key for nin numberes in a PrimaryElementList.
        """
        return self.number

    # -----------------------------------------------------------------
    @property
    def number(self):
        """
        This is the nin number.

        :return: nin number.
        :rtype: str | unicode
        """
        return self._data['number']

    @number.setter
    def number(self, value):
        """
        :param value: nin number.
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
        return old


class NinList(PrimaryElementList):
    """
    Hold a list of Nin instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary nin number in the list (except if the list is empty).

    :param nins: List of nin number records
    :type nins: [dict | Nin]
    """

    def __init__(self, nins, raise_on_unknown=True):
        elements = []

        for this in nins:
            if isinstance(this, Nin):
                nin = this
            else:
                nin = nin_from_dict(this, raise_on_unknown)
            elements.append(nin)

        PrimaryElementList.__init__(self, elements)

    @property
    def primary(self):
        """
        :return: Return the primary Nin.

        There must always be exactly one primary element in the list, so an
        PrimaryElementViolation is raised in case this assertion does not hold.

        :rtype: Nin
        """
        return PrimaryElementList.primary.fget(self)

    @primary.setter
    def primary(self, nin):
        """
        Mark nin as the users primary Nin.

        This is a NinList operation since it needs to atomically update more than one
        element in the list. Marking an element as primary will result in some other element
        loosing it's primary status.

        :param nin: the key of the element to set as primary
        :type  nin: str | unicode
        """
        PrimaryElementList.primary.fset(self, nin)


def nin_from_dict(data, raise_on_unknown=True):
    """
    Create a Nin instance from a dict.

    :param data: Phone number parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: Nin
    """
    return Nin.from_dict(data, raise_on_unknown=raise_on_unknown)
