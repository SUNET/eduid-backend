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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import bson
import copy
import datetime

from eduid_userdb.exceptions import ToUMissingData, ToUHasUnknownData


class ToU(object):
    """
    Generic eduID ToU acceptance object.

    :param data: MongoDB document representing a ToU acceptance
    :type  data: dict
    """
    def __init__(self, data, raise_on_unknown = True):
        self._data_in = copy.deepcopy(data)  # to not modify callers data
        self._data = dict()

        self._parse_check_invalid_tous()

        user_id = self._data_in.pop('user_id')
        if not isinstance(user_id, bson.ObjectId):
            user_id = bson.ObjectId(user_id)
        self._data['user_id'] = user_id

        self._data['version'] = self._data_in.pop('version')
        self._data['source'] = self._data_in.pop('source')

        if 'acceptance_ts' in self._data_in:
            self._data['acceptance_ts'] = self._data_in.pop('acceptance_ts')
        else:
            self._data['acceptance_ts'] = datetime.datetime.utcnow()

        if len(self._data_in) > 0:
            if raise_on_unknown:
                raise ToUHasUnknownData(
                        'ToU {!s}/{!s} unknown data: {!r}'.format(
                    self.user_id, self.version, self._data_in.keys()
                ))
            # Just keep everything that is left as-is
            self._data.update(self._data_in)

    def _parse_check_invalid_tous(self):
        """"
        Part of __init__().

        Check acceptances that can't be loaded for some known reason.
        """
        if 'user_id' not in self._data_in:
            raise ToUMissingData('ToU acceptance {!s} has no user_id'.format(
                        self._data_in))
        if 'version' not in self._data_in:
            raise ToUMissingData('ToU acceptance {!s} has no version'.format(
                        self._data_in))
        if 'source' not in self._data_in:
            raise ToUMissingData('ToU acceptance {!s} has no source'.format(
                        self._data_in))

    def __repr__(self):
        return '<eduID {!s}: {!s}/{!s}/{!s}>'.format(self.__class__.__name__,
                                                self.user_id,
                                                self.version,
                                                self.source,
                                                )

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            raise TypeError('Trying to compare objects of different class')
        return self._data == other._data

    # -----------------------------------------------------------------
    @property
    def user_id(self):
        """
        Get the _id od the user accepting the ToU

        :rtype: bson.ObjectId
        """
        return self._data['_id']

    # -----------------------------------------------------------------
    @property
    def version(self):
        """
        Get the Version of the ToU

        :rtype: str
        """
        return self._data.get('version')

    # -----------------------------------------------------------------
    @property
    def source(self):
        """
        Get the name of the source app for this ToU acceptance

        :rtype: str | unicode
        """
        return self._data.get('source')

    # -----------------------------------------------------------------
    @property
    def acceptance_ts(self):
        """
        Get the timestamp of the ToU acceptance.

        :rtype: datetime
        """
        return self._data.get('acceptance_ts')

    # -----------------------------------------------------------------
    def to_dict(self, old_userdb_format=False):
        """
        Return ToU acceptance data serialized so that it can be stored
        in MongoDB.

        Its usage would be like::

            selector, data = tou.to_dict(old_userdb_format=True)
            tou_collection.update(selector, data, safe=True, upsert=True)

        :param old_userdb_format: Set to True to get the dict
                                  in the old database format.
        :type old_userdb_format: bool

        :return: list of dicts to update MongoDB
        :rtype: list
        """
        if old_userdb_format:
            return ({'_id': self.user_id},
                    {'$push': {
                        'eduid_ToU': {
                            self.version: {
                                'ts': self.acceptance_ts,
                                'source': self.source,
                            }
                        }
                    }})


