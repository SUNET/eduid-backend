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

from eduid_userdb.element import Element, VerifiedElement, _update_something_by
from eduid_userdb.exceptions import UserHasUnknownData, UserDBValueError

__author__ = 'lundberg'


class NinProofingElement(VerifiedElement):
    """
    Elements that can be verified or not.

    Properties of VerifiedElement:

        number
        is_verified
        verified_by
        verified_ts
        verification_code

    :param data: element parameters from database
    :param raise_on_unknown: Raise exception on unknown values in `data' or not.

    :type data: dict
    :type raise_on_unknown: bool
    """
    def __init__(self, data, raise_on_unknown=True, ignore_data=None):
        super(NinProofingElement, self).__init__(data)

        self._data['number'] = data.pop('nin')

        ignore_data = ignore_data or []
        leftovers = [x for x in data.keys() if x not in ignore_data]
        if leftovers:
            if raise_on_unknown:
                raise UserHasUnknownData('{!s} has unknown data: {!r}'.format(
                    self.__class__.__name__,
                    leftovers,
                ))
            # Just keep everything that is left as-is
            self._data.update(data)


class ProofingLetterElement(Element):
    """
        Properties of SentLetterElement:

        letter_sent
        transaction_id
        created_by
        created_ts
    """
    def __init__(self, data, raise_on_unknown=True, ignore_data=None):
        super(ProofingLetterElement, self).__init__(data)

        self._data['is_sent'] = data.pop('letter_sent', False)
        self._data['transaction_id'] = data.pop('transaction_id', None)

        ignore_data = ignore_data or []
        leftovers = [x for x in data.keys() if x not in ignore_data]
        if leftovers:
            if raise_on_unknown:
                raise UserHasUnknownData('{!s} has unknown data: {!r}'.format(
                    self.__class__.__name__,
                    leftovers,
                ))
            # Just keep everything that is left as-is
            self._data.update(data)

    @property
    def is_sent(self):
        """
        :return: True if this is a verified element.
        :rtype: bool
        """
        return self._data['verified']

    @is_sent.setter
    def is_sent(self, value):
        """
        :param value: New verification status
        :type value: bool
        """
        if not isinstance(value, bool):
            raise UserDBValueError("Invalid 'is_sent': {!r}".format(value))
        self._data['is_sent'] = value

    @property
    def transaction_id(self):
        """
        :return: Transaction information from the letter service
        :rtype: str | unicode
        """
        return self._data.get('transaction_id', '')

    @transaction_id.setter
    def transaction_id(self, value):
        """
        :param value: Transaction information from letter service (None is no-op).
        :type value: str | unicode | None
        """
        _update_something_by(self._data, 'transaction_id', value)
