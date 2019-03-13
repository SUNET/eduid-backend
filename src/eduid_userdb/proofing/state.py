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

from __future__ import annotations

import bson
import copy
import datetime

from typing import Dict, Any

from eduid_userdb.exceptions import UserDBValueError
from eduid_userdb.proofing.element import NinProofingElement, SentLetterElement
from eduid_userdb.proofing.element import EmailProofingElement, PhoneProofingElement


__author__ = 'lundberg'


class ProofingState(object):
    def __init__(self, id, eppn, modified_ts):
        self._data: Dict[str, Any] = {}
        self.id = id
        self.eppn = eppn
        self.modified_ts = modified_ts

    @classmethod
    def _default_from_dict(cls, data, fields):
        _leftovers = [x for x in data.keys() if x not in fields]
        if _leftovers:
            raise UserDBValueError(f'{type(cls)}.from_dict() unknown data: {_leftovers}')

        return cls(**data)


    def __repr__(self):
        return '<eduID {!s}: {!s}>'.format(self.__class__.__name__, self.eppn)

    @property
    def id(self) -> bson.ObjectId:
        """ Get state id. """
        return self._data['_id']

    @id.setter
    def id(self, value: bson.ObjectId):
        self._data['_id'] = value

    @property
    def reference(self):
        """
        Audit reference to help cross reference audit log and events

        :rtype: six.string_types
        """
        return '{}'.format(self.id)

    @property
    def eppn(self):
        """
        Get the user's eppn

        :rtype: six.string_types
        """
        return self._data['eduPersonPrincipalName']

    @eppn.setter
    def eppn(self, value: str):
        self._data['eduPersonPrincipalName'] = value

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

    def is_expired(self, timeout_seconds):
        """
        Check whether the code is expired.

        :param timeout_seconds: the number of seconds a code is valid
        :type timeout_seconds: int

        :rtype: bool
        """
        delta = datetime.timedelta(seconds=timeout_seconds)
        expiry_date = self.modified_ts + delta
        now = datetime.datetime.now(tz=self.modified_ts.tzinfo)
        return expiry_date < now


class NinProofingState(ProofingState):
    def __init__(self, id, eppn, modified_ts, nin: NinProofingElement):
        super().__init__(id=id, eppn=eppn, modified_ts=modified_ts)
        self._data['nin'] = nin

    @classmethod
    def from_dict(cls, data) -> NinProofingState:
        _data = copy.deepcopy(data)  # to not modify callers data
        data['nin'] = NinProofingElement(data=data['nin'])
        _known_data = ['id', 'eppn', 'modified_ts', 'nin']
        return cls._default_from_dict(data, _known_data)

    @property
    def nin(self) -> NinProofingElement:
        return self._data['nin']

    def to_dict(self):
        res = super().to_dict()
        res['nin'] = self.nin.to_dict()
        return res


class LetterProofingState(NinProofingState):
    def __init__(self, id, eppn, modified_ts, nin, proofing_letter: dict):
        super().__init__(id=id, eppn=eppn, modified_ts=modified_ts, nin=nin)
        _proofing_letter = copy.deepcopy(proofing_letter)  # to not modify callers data
        self._data['proofing_letter'] = SentLetterElement(data=_proofing_letter)

    @classmethod
    def from_dict(cls, data) -> LetterProofingState:
        _known_data = ['id', 'eppn', 'modified_ts', 'nin', 'proofing_letter']
        return cls._default_from_dict(data, _known_data)

    @property
    def proofing_letter(self) -> SentLetterElement:
        return self._data['proofing_letter']

    def to_dict(self):
        res = super().to_dict()
        res['proofing_letter'] = self.proofing_letter.to_dict()
        return res


class OrcidProofingState(ProofingState):
    def __init__(self, id, eppn, modified_ts, state, nonce):
        super().__init__(id=id, eppn=eppn, modified_ts=modified_ts)
        self._data['state'] = state
        self._data['nonce'] = nonce

    @classmethod
    def from_dict(cls, data) -> OrcidProofingState:
        _known_data = ['id', 'eppn', 'modified_ts', 'state', 'nonce']
        return cls._default_from_dict(data, _known_data)

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


class OidcProofingState(NinProofingState):

    def __init__(self, id, eppn, modified_ts, state, nonce, token, nin):
        super().__init__(id=id, eppn=eppn, modified_ts=modified_ts, nin=nin)
        self._data['token'] = token
        self._data['state'] = state
        self._data['nonce'] = nonce

    @property
    def token(self):
        """
        :rtype: str | unicode
        """
        return self._data['token']

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


class EmailProofingState(ProofingState):
    def __init__(self, id, eppn, modified_ts, verification):
        super().__init__(id, eppn, modified_ts)
        _verification = copy.deepcopy(verification)  # to not modify callers data
        self._data['verification'] = EmailProofingElement(data=_verification)

    @property
    def verification(self):
        """
        :rtype: EmailProofingElement
        """
        return self._data['verification']

    def to_dict(self):
        res = super(EmailProofingState, self).to_dict()
        res['verification'] = self.verification.to_dict()
        return res


class PhoneProofingState(ProofingState):
    def __init__(self, id, eppn, modified_ts, verification):
        super().__init__(id, eppn, modified_ts)
        _verification = copy.deepcopy(verification)  # to not modify callers data
        self._data['verification'] = PhoneProofingElement(data=_verification)

    @property
    def verification(self):
        """
        :rtype: PhoneProofingElement
        """
        return self._data['verification']

    def to_dict(self):
        res = super(PhoneProofingState, self).to_dict()
        res['verification'] = self.verification.to_dict()
        return res

