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

import bson
import copy
import datetime

from .proofing_element import NinProofingElement, SentLetterElement
from .proofing_element import EmailProofingElement, SentEmailElement
from eduid_userdb.exceptions import UserHasUnknownData

__author__ = 'lundberg'


class ProofingState(object):
    def __init__(self, data, raise_on_unknown=True):
        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        # things without setters
        # _id
        _id = self._data_in.pop('_id', None)
        if _id is None:
            _id = bson.ObjectId()
        if not isinstance(_id, bson.ObjectId):
            _id = bson.ObjectId(_id)
        self._data['_id'] = _id
        # eppn
        eppn = self._data_in.pop('eduPersonPrincipalName')
        self._data['eduPersonPrincipalName'] = eppn

        self.modified_ts = self._data_in.pop('modified_ts', None)

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s} unknown data: {!r}'.format(
                    self.eppn, self._data_in.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    def __repr__(self):
        return '<eduID {!s}: {!s}>'.format(self.__class__.__name__, self.eppn)

    @property
    def eppn(self):
        """
        Get the user's eppn

        :rtype: str | unicode
        """
        return self._data['eduPersonPrincipalName']

    @property
    def modified_ts(self):
        """
        :return: Timestamp of last modification in the database.
                 None if User has never been written to the database.
        :rtype: datetime.datetime | None
        """
        return self._data.get('modified_ts')

    @modified_ts.setter
    def modified_ts(self, value):
        """
        :param value: Timestamp of modification.
                      Value None is ignored, True is short for datetime.utcnow().
        :type value: datetime.datetime | True | None
        """
        if value is None:
            return
        if value is True:
            value = datetime.datetime.utcnow()
        self._data['modified_ts'] = value

    def to_dict(self):
        res = copy.copy(self._data)  # avoid caller messing with our _data
        return res


class LetterProofingState(ProofingState):
    def __init__(self, data, raise_on_unknown=True):
        self._data_in = copy.deepcopy(data)  # to not modify callers data
        _nin = NinProofingElement(data=self._data_in.pop('nin'))
        _proofing_letter = SentLetterElement(self._data_in.pop('proofing_letter', {}))

        ProofingState.__init__(self, self._data_in, raise_on_unknown)
        self._data['nin'] = _nin
        self._data['proofing_letter'] = _proofing_letter

    @property
    def nin(self):
        """
        :rtype: NinProofingElement
        """
        return self._data['nin']

    @property
    def proofing_letter(self):
        """
        :rtype: ProofingLetterElement
        """
        return self._data['proofing_letter']

    def to_dict(self):
        res = super(LetterProofingState, self).to_dict()
        res['nin'] = self.nin.to_dict()
        res['proofing_letter'] = self.proofing_letter.to_dict()
        return res


class EmailProofingState(ProofingState):
    def __init__(self, data, raise_on_unknown=True):
        self._data_in = copy.deepcopy(data)  # to not modify callers data
        _email = EmailProofingElement(data=self._data_in.pop('email'))
        _proofing_email = SentEmailElement(self._data_in.pop('proofing_email', {}))

        ProofingState.__init__(self, self._data_in, raise_on_unknown)
        self._data['email'] = _email
        self._data['proofing_email'] = _proofing_email

    @property
    def email(self):
        """
        :rtype: EmailProofingElement
        """
        return self._data['email']

    @property
    def proofing_email(self):
        """
        :rtype: ProofingEmailElement
        """
        return self._data['proofing_email']

    def to_dict(self):
        res = super(EmailProofingState, self).to_dict()
        res['email'] = self.email.to_dict()
        res['proofing_email'] = self.proofing_email.to_dict()
        return res


class OidcProofingState(ProofingState):
    def __init__(self, data, raise_on_unknown=True):
        self._data_in = copy.deepcopy(data)  # to not modify callers data
        # Remove from _data_in before init super class
        state = self._data_in.pop('state')
        nonce = self._data_in.pop('nonce')

        ProofingState.__init__(self, self._data_in, raise_on_unknown)

        self._data['state'] = state
        self._data['nonce'] = nonce

    @property
    def state(self):
        """
        :rtype: str | unicode
        """
        return self._data['state']

    @property
    def nonce(self):
        """
        :rtype: str | unicode
        """
        return self._data['nonce']

