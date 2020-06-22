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

import copy
from datetime import datetime
from typing import Any, Dict, List, Optional, Type, Union

from bson import ObjectId

from eduid_userdb.element import DuplicateElementViolation, Element, ElementList
from eduid_userdb.exceptions import BadEvent, EventHasUnknownData, UserDBValueError


# Unique type for the events 'key' property. Not created with EventId = NewType('EventId', ObjectId)
# because of a problem with mypy not deducing the type of bson.ObjectId:
#   src/eduid_userdb/event.py:45: error: Argument 2 to NewType(...) must be subclassable (got "Any")
class EventId(ObjectId):
    pass


class Event(Element):
    """
    :param data: Event parameters from database

    :type data: dict
    """

    def __init__(
        self,
        application: Optional[str] = None,
        created_ts: Optional[Union[datetime, bool]] = None,
        modified_ts: Optional[Union[datetime, bool]] = None,
        data: Optional[Dict[str, Any]] = None,
        event_type: Optional[str] = None,
        event_id: Optional[str] = None,
        raise_on_unknown: bool = True,
        called_directly: bool = True,
        ignore_data: Optional[List[str]] = None,
    ):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            if modified_ts is None:
                modified_ts = created_ts
            data = dict(
                created_by=application,
                created_ts=created_ts,
                modified_ts=modified_ts,
                event_type=event_type,
                event_id=event_id,
            )
        # modified_ts was not part of Event from the start, make sure it gets added and default to created_ts
        if 'modified_ts' not in data:
            data['modified_ts'] = data.get('created_ts', None)

        super().__init__(data, called_directly=called_directly)
        self.event_type = data.pop('event_type', None)
        if 'id' in data:  # Compatibility for old format
            data['event_id'] = data.pop('id')
        self.event_id = data.pop('event_id')

        ignore_data = ignore_data or []
        leftovers = [x for x in data.keys() if x not in ignore_data]
        if leftovers:
            if raise_on_unknown:
                raise EventHasUnknownData('Event {!r} unknown data: {!r}'.format(self.event_id, leftovers,))
            # Just keep everything that is left as-is
            self._data.update(data)

    @classmethod
    def from_dict(cls: Type[Event], data: Dict[str, Any], raise_on_unknown: bool = True) -> Event:
        """
        Construct event from a data dict.
        """
        return cls(data=data, called_directly=False, raise_on_unknown=raise_on_unknown)

    # -----------------------------------------------------------------
    @property
    def key(self) -> EventId:
        """ Return the element that is used as key for events in an ElementList. """
        return EventId(self.event_id)

    # -----------------------------------------------------------------
    @property
    def event_type(self) -> str:
        """ This is the event type. """
        return self._data['event_type']

    @event_type.setter
    def event_type(self, value: str):
        if value is None:
            return
        if not isinstance(value, str):
            raise UserDBValueError("Invalid 'event_type': {!r}".format(value))
        self._data['event_type'] = str(value.lower())

    @property
    def event_id(self) -> EventId:
        """ This is a unique id for this event. """
        return self._data['event_id']

    @event_id.setter
    def event_id(self, value: EventId):
        if not isinstance(value, ObjectId):
            raise UserDBValueError("Invalid 'event_id': {!r}".format(value))
        self._data['event_id'] = value

    # -----------------------------------------------------------------
    def to_dict(self, mixed_format: bool = False) -> Dict[str, Any]:
        """
        Convert Element to a dict, that can be used to reconstruct the Element later.

        :param mixed_format: Tag each Event with the event_type. Used when list has multiple types of events.
        """
        res = copy.copy(self._data)  # avoid caller messing with our _data
        if not mixed_format and 'event_type' in res:
            del res['event_type']
        return res


class EventList(ElementList):
    """
    Hold a list of Event instances.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there no duplicates in the list.

    :param events: List of events
    :param raise_on_unknown: Raise EventHasUnknownData if unrecognized data is encountered
    :param event_class: Enforce all elements are of this type

    :type events: [dict | Event]
    :type raise_on_unknown: bool
    :type event_class: object
    """

    def __init__(self, events, raise_on_unknown=True, event_class: Type[Event] = Event):
        self._event_class = event_class
        ElementList.__init__(self, elements=[])

        if not isinstance(events, list):
            raise UserDBValueError('events should be a list')

        for this in events:
            if isinstance(this, self._event_class):
                self.add(this)
            else:
                event: Event
                if 'event_type' in this:
                    event = event_from_dict(this, raise_on_unknown=raise_on_unknown)
                else:
                    event = self._event_class.from_dict(this)
                self.add(event)

    def add(self, event) -> None:
        """ Add an event to the list. """
        if not isinstance(event, self._event_class):
            raise UserDBValueError("Invalid event: {!r} (expected {!r})".format(event, self._event_class))
        existing = self.find(event.key)
        if existing:
            if event.to_dict() == existing.to_dict():
                # Silently accept duplicate identical events to clean out bad entrys from the database
                return
            raise DuplicateElementViolation("Event {!s} already in list".format(event.key))
        super(EventList, self).add(event)

    def to_list_of_dicts(self, mixed_format: bool = False) -> List[Dict[str, Any]]:
        """
        Get the elements in a serialized format that can be stored in MongoDB.

        :param mixed_format: Tag each Event with the event_type. Used when list has multiple types of events.
        """
        return [this.to_dict(mixed_format=mixed_format) for this in self._elements if isinstance(this, Event)]


def event_from_dict(data: Dict[str, Any], raise_on_unknown: bool = True):
    """
    Create an Event instance (probably really a subclass of Event) from a dict.

    :param data: Password parameters from database
    :param raise_on_unknown: Raise EventHasUnknownData if unrecognized data is encountered
    """
    if 'event_type' not in data:
        raise UserDBValueError('No event type specified')
    if data['event_type'] == 'tou_event':
        from eduid_userdb.tou import ToUEvent  # avoid cyclic dependency by importing this here

        return ToUEvent.from_dict(data=data, raise_on_unknown=raise_on_unknown)
    raise BadEvent('Unknown event_type in data: {!s}'.format(data['event_type']))
