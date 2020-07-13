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

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type

from bson import ObjectId

from eduid_userdb.element import DuplicateElementViolation, Element, ElementList
from eduid_userdb.exceptions import BadEvent, UserDBValueError


# Unique type for the events 'key' property. Not created with EventId = NewType('EventId', ObjectId)
# because of a problem with mypy not deducing the type of bson.ObjectId:
#   src/eduid_userdb/event.py:45: error: Argument 2 to NewType(...) must be subclassable (got "Any")
class EventId(ObjectId):
    pass


@dataclass
class Event(Element):
    """
    """
    data: Optional[Dict[str, Any]] = None
    event_type: Optional[str] = None
    event_id: Optional[str] = None

    name_mapping = {'id': 'event_id'}

    @property
    def key(self) -> EventId:
        """ Return the element that is used as key for events in an ElementList. """
        return EventId(self.event_id)


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

    def __init__(self, events, event_class: Type[Event] = Event):
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
                    event = event_from_dict(this)
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


def event_from_dict(data: Dict[str, Any]):
    """
    Create an Event instance (probably really a subclass of Event) from a dict.

    :param data: Password parameters from database
    """
    if 'event_type' not in data:
        raise UserDBValueError('No event type specified')
    if data['event_type'] == 'tou_event':
        from eduid_userdb.tou import ToUEvent  # avoid cyclic dependency by importing this here

        return ToUEvent.from_dict(data=data)
    raise BadEvent('Unknown event_type in data: {!s}'.format(data['event_type']))
