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

__author__ = 'ft'

from eduid_userdb import User
from eduid_userdb.exceptions import UserMissingData


class ToUUser(User):
    """
    Subclass of eduid_userdb.User with
    the eduid-actions plugin for ToU specific data.
    """

    def __init__(self, userid = None, tou = None, data = None):
        if data is None:
            data = dict(_id = userid,
                        tou = tou,
                        eduPersonPrincipalName='dummy')

        User.__init__(self, data = data)

    def _parse_check_invalid_users(self):
        """
        Part of User.__init__().

        Check users that can't be loaded for some known reason.
        """
        if '_id' not in self._data_in or not self._data_in['_id']:
            raise UserMissingData('Attempting to record a ToU acceptance '
                                  'for an unidentified user.')
        if 'tou' not in self._data_in or self._data_in['tou'] is None:
            raise UserMissingData('Attempting to record the acceptance of '
                                  'an unknown version of the ToU for '
                                  'the user with id ' + str(userid))

