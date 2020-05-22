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

__author__ = 'eperez'

from copy import deepcopy
from typing import Optional, Union

import bson

from eduid_userdb import User
from eduid_userdb.credentials import CredentialList
from eduid_userdb.exceptions import UserHasUnknownData, UserMissingData


class ChpassUser(User):
    """
    Subclass of eduid_userdb.User with
    the eduid-actions plugin for password change specific data.

    :param userid: user id
    :type userid: bson.ObjectId
    :param passwords: Password list
    :type passwords: list
    :param data: userid and password list
    :type data: dict
    :param raise_on_unknown: whether to raise an exception if
                             there is unknown data in the data dict
    :type raise_on_unknown: bool
    """

    def __init__(self, userid=None, passwords=None, data=None, raise_on_unknown=True):
        """
        """
        if data is None:
            data = {'_id': userid, 'passwords': passwords}

        self.check_for_missing_data(data)

        self._data_in = deepcopy(data)
        self._data = dict()

        # things without setters
        _id = self._data_in.pop('_id', None)
        if not isinstance(_id, bson.ObjectId):
            _id = bson.ObjectId(_id)
        self._data['_id'] = _id

        self._credentials = CredentialList(self._data_in.pop('passwords', []))

        self.modified_ts = self._data_in.pop('modified_ts', None)

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s} unknown data: {!r}'.format(self.user_id, self._data_in.keys()))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    @classmethod
    def construct_user(
        cls,
        userid: Optional[Union[bson.ObjectId, str]] = None,
        **kwargs
    ):
        """
        """
        if userid is not None:
            kwargs['_id'] = userid

        cls.check_for_missing_data(kwargs)

        return User.construct_user(**kwargs)

    @staticmethod
    def check_for_missing_data(data):
        if '_id' not in data or data['_id'] is None:
            raise UserMissingData('Attempting to record passwords ' 'for an unidentified user.')
        if 'passwords' not in data or data['passwords'] is None:
            raise UserMissingData(
                'Attempting to record ' 'an unknown password for ' 'the user with id ' + str(data['_id'])
            )

    @classmethod
    def from_central_user(cls, user):
        """
        Create user from generic user.

        :param user: user from central db
        :type user: eduid_userdb.user.User
        """
        data = {'_id': user.user_id, 'passwords': user.credentials.to_list_of_dicts(), 'modified_ts': user.modified_ts}
        return cls(data=data)

    # -----------------------------------------------------------------
    def to_dict(self, old_userdb_format=False):
        """
        Return user data serialized into a dict that can be stored in MongoDB.

        :param old_userdb_format: Set to True to get the dict in the old database format.
        :type old_userdb_format: bool

        :return: User as dict
        :rtype: dict
        """
        res = deepcopy(self._data)  # avoid caller messing up our private _data
        res['passwords'] = self.credentials.to_list_of_dicts(old_userdb_format=old_userdb_format)
        return res
