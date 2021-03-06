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
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type

from eduid.userdb.event import Event, EventList
from eduid.userdb.exceptions import EduIDUserDBError, UserDBValueError


@dataclass
class ToUEvent(Event):
    """
    A record of a user's acceptance of a particular version of the Terms of Use.
    """

    created_by: str
    version: Optional[str] = None

    @classmethod
    def _from_dict_transform(cls: Type[ToUEvent], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        """
        data = super()._from_dict_transform(data)

        if 'event_type' not in data:
            data['event_type'] = 'tou_event'

        return data

    def is_expired(self, interval_seconds: int) -> bool:
        """
        Check whether the ToU event needs to be reaccepted.

        :param interval_seconds: the max number of seconds between a users acceptance of the ToU
        """
        if not isinstance(self.modified_ts, datetime.datetime):
            if self.modified_ts is None:
                return False
            raise UserDBValueError(f'Malformed modified_ts: {self.modified_ts!r}')
        delta = datetime.timedelta(seconds=interval_seconds)
        expiry_date = self.modified_ts + delta
        now = datetime.datetime.now(tz=self.modified_ts.tzinfo)
        return expiry_date < now


class ToUList(EventList):
    """
    List of ToUEvents.

    TODO: Add, find and remove ought to operate on element.key and not element.version.
          has_accepted() is the interface to find an ToU event using a version number.
    """

    def __init__(self, events):
        EventList.__init__(self, events, event_class=ToUEvent)

    def add(self, event: ToUEvent) -> None:
        """ Add a ToUEvent to the list. """
        if event.version is None:
            raise ValueError('Invalid ToUEvent without version')

        existing = self.find(event.version)
        if existing:
            if event.created_ts >= existing.created_ts:
                # Silently replace existing events with newer ones to flush out duplicate events in the database
                self.remove(existing.version)
        super().add(event)

    def find(self, version: str) -> Optional[ToUEvent]:
        """
        Find an ToUEvent from the ToUList using ToU version.

        :param version: ToU version to find
        """
        res = [this for this in self.elements if this.version == version]
        if len(res) == 1:
            return res[0]
        if len(res) > 1:
            raise EduIDUserDBError(f'More than one ToUEvent with version {version} found')
        return None

    def has_accepted(self, version: str, reaccept_interval: int):
        """
        Check if the user has accepted a particular version of the ToU.

        :param version: Version of ToU
        :param reaccept_interval: Time between accepting and the need to reaccept (default 3 years)

        :return: True or False
        :rtype: bool
        """
        # All users have implicitly accepted the first ToU version (info stored in another collection)
        if version in ['2014-v1', '2014-dev-v1']:
            return True
        for this in self.elements:
            if this.version == version and not this.is_expired(interval_seconds=reaccept_interval):
                return True
        return False

    @property
    def elements(self) -> List[ToUEvent]:
        """ Return typing friendly list of ToU events """
        return [x for x in self._elements if isinstance(x, ToUEvent)]
