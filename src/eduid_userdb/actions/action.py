#
# Copyright (c) 2014-2015 NORDUnet A/S
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
# Author : Enrique Perez <enrique@cazalla.net>
#

import bson
import copy

from eduid_userdb.exceptions import ActionMissingData, ActionHasUnknownData

VALID_SUBJECT_VALUES = ['physical person']


class Action(object):
    """
    Generic eduID action object.

    :param data: MongoDB document representing an action
    :type  data: dict
    """
    def __init__(self, data, raise_on_unknown = True):
        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        self._parse_check_invalid_actions()

        # ensure _id is always an ObjectId
        _id = self._data_in.pop('_id', None)
        if _id is None:
            _id = bson.ObjectId()
        elif not isinstance(_id, bson.ObjectId):
            _id = bson.ObjectId(_id)

        # things without setters
        self._data['_id'] = _id
        self._data['user_oid'] = self._data_in.pop('user_oid')
        self._data['action'] = self._data_in.pop('action')
        self._data['preference'] = self._data_in.pop('preference', 100)
        self._data['session'] = self._data_in.pop('session', '')
        self._data['params'] = self._data_in.pop('params', {})

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise ActionHasUnknownData('Action {!s} unknown data: {!r}'.format(
                    self.action_id, self._data_in.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    def _parse_check_invalid_actions(self):
        """"
        Part of __init__().

        Check actions that can't be loaded for some known reason.
        """
        if self._data_in.get('user_oid') is None:
            raise ActionMissingData('Action {!s} has no user_oid'.format(
                self._data_in.get('_id')))
        if self._data_in.get('action') is None:
            raise ActionMissingData('Action {!s} has no action'.format(
                self._data_in.get('_id')))

    def __repr__(self):
        return '<eduID {!s}: {!s} for {!s}>'.format(self.__class__.__name__,
                                                    self.action_type,
                                                    self.user_id,
                                                    )

    __str__ = __repr__

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            raise TypeError('Trying to compare objects of different class')
        return self._data == other._data

    # -----------------------------------------------------------------
    @property
    def action_id(self):
        """
        Get the actions's oid in MongoDB.

        :rtype: bson.ObjectId
        """
        return self._data['_id']

    # -----------------------------------------------------------------
    @property
    def user_id(self):
        """
        Get the actions's user_oid in MongoDB.

        :rtype: bson.ObjectId
        """
        return self._data['user_oid']

    # -----------------------------------------------------------------
    @property
    def action_type(self):
        """
        Get the action type.

        :rtype: str
        """
        return self._data.get('action')

    # -----------------------------------------------------------------
    @property
    def session(self):
        """
        Get the IdP session for the action.

        :rtype: str
        """
        return self._data.get('session')

    # -----------------------------------------------------------------
    @property
    def preference(self):
        """
        Get the action preference.

        :rtype: str
        """
        return int(self._data.get('preference'))

    # -----------------------------------------------------------------
    @property
    def params(self):
        """
        Get the action params.

        :rtype: str
        """
        return self._data.get('params')

    # -----------------------------------------------------------------
    def to_dict(self):
        """
        Return action data serialized into a dict that can be stored in MongoDB.

        :return: Action as dict
        :rtype: dict
        """
        res = copy.deepcopy(self._data)  # avoid caller messing up our private _data
        return res
