#
# Copyright (c) 2015 NORDUnet A/S
# Copyright (c) 2018 SUNET
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
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Type

from bson import ObjectId
from pydantic import validator

from eduid.userdb.event import Event, EventList
from eduid.userdb.exceptions import UserDBValueError
from eduid.userdb.util import utc_now


class ToUEvent(Event):
    """
    A record of a user's acceptance of a particular version of the Terms of Use.
    """

    created_by: str
    version: str

    @validator('version')
    def _validate_tou_version(cls, v):
        if not v:
            raise ValueError('ToU must have a version')
        if not isinstance(v, str):
            raise TypeError('ToU version must be a string')
        return v

    @classmethod
    def _from_dict_transform(cls: Type[ToUEvent], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        """
        data = super()._from_dict_transform(data)

        if 'event_type' not in data:
            data['event_type'] = 'tou_event'

        if 'event_id' in data and isinstance(data['event_id'], ObjectId):
            data['event_id'] = str(data['event_id'])

        return data

    def is_expired(self, interval_seconds: int) -> bool:
        """
        Check whether the ToU event needs to be re-accepted.

        :param interval_seconds: the max number of seconds between a users acceptance of the ToU
        """
        if not isinstance(self.modified_ts, datetime.datetime):
            if self.modified_ts is None:
                return False
            raise UserDBValueError(f'Malformed modified_ts: {self.modified_ts!r}')
        delta = datetime.timedelta(seconds=interval_seconds)
        expiry_date = self.modified_ts + delta
        return expiry_date < utc_now()


class ToUList(EventList[ToUEvent]):
    """
    List of ToUEvents.

    TODO: Add, find and remove ought to operate on element.key and not element.version.
          has_accepted() is the interface to find an ToU event using a version number.
    """

    @classmethod
    def from_list_of_dicts(cls: Type[ToUList], items: List[Dict[str, Any]]) -> ToUList:
        return cls(elements=[ToUEvent.from_dict(this) for this in items])

    def has_accepted(self, version: str, reaccept_interval: int) -> bool:
        """
        Check if the user has accepted a particular version of the ToU.

        :param version: Version of ToU
        :param reaccept_interval: Time between accepting and the need to reaccept (default 3 years)
        """
        # All users have implicitly accepted the first ToU version (info stored in another collection)
        if version in ['2014-v1', '2014-dev-v1']:
            return True
        for this in self.elements:
            if not isinstance(this, ToUEvent):
                raise UserDBValueError(f'Event {repr(this)} is not of type ToUEvent')

            if this.version == version and not this.is_expired(interval_seconds=reaccept_interval):
                return True
        return False
