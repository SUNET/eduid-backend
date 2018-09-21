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

import bson
from copy import deepcopy

from eduid_userdb import User
from eduid_userdb.exceptions import UserMissingData, UserHasUnknownData


class ToUUser(User):
    """
    Subclass of eduid_userdb.User with
    the eduid-actions plugin for ToU specific data.

    :param eppn: eppn
    :type eppn: str
    :param tou: ToU  list
    :type tou: list
    :param data: eppn and tou
    :type data: dict
    :param raise_on_unknown: whether to raise an exception if
                             there is unknown data in the data dict
    :type raise_on_unknown: bool
    """

    def __init__(self, eppn = None, tou = None, data = None,
                                         raise_on_unknown = True):
        """
        """
        if data is None:
            data = {'eppn': eppn, 'tou': tou}

        if 'eppn' not in data or data['eppn'] is None:
            raise UserMissingData('Attempting to record a ToU acceptance '
                                  'for an unidentified user.')
        if 'tou' not in data or data['tou'] is None:
            raise UserMissingData('Attempting to record the acceptance of '
                                  'an unknown version of the ToU for '
                                  'the user with eppn ' + str(data['eppn']))

        self._data_in = deepcopy(data)
        self._data = dict()

        # things without setters
        self.eppn = self._data_in.pop('eppn', None)
        self._parse_tous()

        self.modified_ts = self._data_in.pop('modified_ts', None)

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise UserHasUnknownData('User {!s} unknown data: {!r}'.format(
                    self.eppn, self._data_in.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

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
        res['tou'] = self.tou.to_list_of_dicts(old_userdb_format=old_userdb_format)
        return res
