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

from abc import ABC
from typing import Any, Dict, Generic, Optional, Type, TypeVar

from bson import ObjectId
from pydantic import validator

from eduid.userdb.element import Element, ElementList, ListElement
from eduid.userdb.exceptions import BadEvent, UserDBValueError


# Unique type for the events 'key' property. Not created with EventId = NewType('EventId', ObjectId)
# because of a problem with mypy not deducing the type of bson.ObjectId:
#   src/eduid_userdb/event.py:45: error: Argument 2 to NewType(...) must be subclassable (got "Any")
class EventId(ObjectId):
    pass


TEventSubclass = TypeVar('TEventSubclass', bound='Event')


class Event(Element):
    """
    """

    data: Optional[Dict[str, Any]] = None
    event_type: Optional[str] = None
    event_id: Optional[EventId] = None
    # This is a short-term hack to deploy new dataclass based events without
    # any changes to data in the production database. Remove after a burn-in period.
    no_event_type_in_db: bool = False

    @validator('event_id', pre=True)
    def event_id_objectid(cls, v):
        """ Turn string into EventId """
        if isinstance(v, str):
            v = EventId(v)
        if not isinstance(v, EventId):
            raise TypeError('must be a string or ObjectId')
        return v

    @property
    def key(self) -> EventId:
        """ Return the element that is used as key for events in an ElementList. """
        return EventId(self.event_id)

    @classmethod
    def _from_dict_transform(cls: Type[TEventSubclass], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if 'event_type' not in data:
            data['no_event_type_in_db'] = True  # Remove this line when Event.no_event_type_in_db is removed

        if 'id' in data:
            data['event_id'] = data.pop('id')

        data['event_id'] = EventId(data['event_id'])

        return data

    def _to_dict_transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        data = super()._to_dict_transform(data)

        # If there was no event_type in the data that was loaded from the database,
        # don't write one back if it matches the implied one of 'tou_event'
        if 'no_event_type_in_db' in data:
            if data.pop('no_event_type_in_db') is True:
                if 'event_type' in data:
                    del data['event_type']

        return data


class EventList(ElementList[ListElement], Generic[ListElement], ABC):
    """
    Hold a list of Event instances.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there no duplicates in the list.
    """

    pass


def event_from_dict(data: Dict[str, Any]):
    """
    Create an Event instance (probably really a subclass of Event) from a dict.

    :param data: Password parameters from database
    """
    if 'event_type' not in data:
        raise UserDBValueError('No event type specified')
    if data['event_type'] == 'tou_event':
        from eduid.userdb.tou import ToUEvent  # avoid cyclic dependency by importing this here

        return ToUEvent.from_dict(data=data)
    raise BadEvent('Unknown event_type in data: {!s}'.format(data['event_type']))
