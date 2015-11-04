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

from .proofing_element import NinProofingElement, ProofingLetterElement
from eduid_userdb.exceptions import UserHasUnknownData

__author__ = 'lundberg'


class ProofingUser(object):
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
        # user_id
        user_id = self._data_in.pop('user_id')
        if not isinstance(_id, bson.ObjectId):
            user_id = bson.ObjectId(_id)
        self._data['user_id'] = user_id

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s} unknown data: {!r}'.format(
                    self.user_id, self._data_in.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    def __repr__(self):
        return '<eduID {!s}: {!s}>'.format(self.__class__.__name__, self.user_id)

    @property
    def user_id(self):
        """
        Get the user's oid in MongoDB.

        :rtype: bson.ObjectId
        """
        return self._data['user_id']


class NinProofingUser(ProofingUser):
    def __init__(self, data, raise_on_unknown=True):
        _nin = NinProofingElement(data)
        ProofingUser.__init__(self, data, raise_on_unknown)
        self._data['nin'] = _nin

    @property
    def nin(self):
        """
        Get the user's oid in MongoDB.

        :rtype: NinProofingElement
        """
        return self._data['nin']

    def to_dict(self):
        """
        Return user data serialized into a dict that can be stored in MongoDB.

        :return: User as dict
        :rtype: dict
        """
        res = copy.copy(self._data)  # avoid caller messing up our private _data
        res['nin'] = self.nin.to_dict()
        return res


class LetterNinProofingUser(NinProofingUser):
    def __init__(self, data, raise_on_unknown=True):

        _proofing_letter = ProofingLetterElement(data)
        NinProofingUser.__init__(self, data, raise_on_unknown)
        self._data['proofing_letter'] = _proofing_letter


