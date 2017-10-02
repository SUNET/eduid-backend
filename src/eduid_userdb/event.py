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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import copy

from bson import ObjectId
from six import string_types
from eduid_userdb.element import Element, ElementList, DuplicateElementViolation
from eduid_userdb.exceptions import UserDBValueError, BadEvent, EventHasUnknownData


class Event(Element):
    """
    :param data: Event parameters from database

    :type data: dict
    """
    def __init__(self, application=None, created_ts=None, data=None, event_type=None, event_id=None,
                 raise_on_unknown=True, ignore_data = None):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(created_by = application,
                        created_ts = created_ts,
                        event_type = event_type,
                        id = event_id,
                        )
        Element.__init__(self, data)
        self.event_type = data.pop('event_type', None)
        if 'id' in data:  # TODO: Load and save all users in the database to replace id with credential_id
            data['event_id'] = data.pop('id')
        self.event_id = data.pop('event_id')

        ignore_data = ignore_data or []
        leftovers = [x for x in data.keys() if x not in ignore_data]
        if leftovers:
            if raise_on_unknown:
                raise EventHasUnknownData('Event {!r} unknown data: {!r}'.format(
                    self.event_id, leftovers,
                ))
            # Just keep everything that is left as-is
            self._data.update(data)

    # -----------------------------------------------------------------
    @property
    def key(self):
        """
        Return the element that is used as key for events in an ElementList.
        """
        return self.event_id

    # -----------------------------------------------------------------
    @property
    def event_type(self):
        """
        This is the event type.

        :return: Event type.
        :rtype: str
        """
        return self._data['event_type']

    @event_type.setter
    def event_type(self, value):
        """
        :param value: event type.
        :type value: str | unicode
        """
        if value is None:
            return
        if not isinstance(value, string_types):
            raise UserDBValueError("Invalid 'event_type': {!r}".format(value))
        self._data['event_type'] = str(value.lower())

    @property
    def event_id(self):
        """
        This is a unique id for this event.

        :return: Unique ID of event.
        :rtype: bson.ObjectId
        """
        return self._data['event_id']

    @event_id.setter
    def event_id(self, value):
        """
        :param value: Unique ID of event.
        :type value: bson.ObjectId
        """
        if not isinstance(value, ObjectId):
            raise UserDBValueError("Invalid 'id': {!r}".format(value))
        self._data['event_id'] = value

    # -----------------------------------------------------------------
    def to_dict(self, old_userdb_format=False, mixed_format=False):
        """
        Convert Element to a dict, that can be used to reconstruct the
        Element later.

        :param old_userdb_format: Ignored, there is no old format for events.
        :param mixed_format: Tag each Event with the event_type. Used when list has multiple types of events.
        :type old_userdb_format: bool
        :type mixed_format: bool
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

    def __init__(self, events, raise_on_unknown=True, event_class=Event):
        self._event_class = event_class
        elements = []
        ElementList.__init__(self, elements)

        if not isinstance(events, list):
            raise UserDBValueError('events should be a list')

        for this in events:
            if isinstance(this, self._event_class):
                self.add(this)
            else:
                if 'event_type' in this:
                    event = event_from_dict(this, raise_on_unknown=raise_on_unknown)
                else:
                    event = self._event_class(data=this)
                self.add(event)

    def add(self, event):
        """
        Add an event to the list.

        :param event: Event to add.
        :type event: Event
        """
        if not isinstance(event, self._event_class):
            raise UserDBValueError("Invalid event: {!r} (expected {!r})".format(event, self._event_class))
        if self.find(event.key):
            raise DuplicateElementViolation("event {!s} already in list".format(event.key))
        super(EventList, self).add(event)

    def to_list_of_dicts(self, old_userdb_format=False, mixed_format=False):
        """
        Get the elements in a serialized format that can be stored in MongoDB.

        :param old_userdb_format: Set to True to get data back in legacy format.
        :param mixed_format: Tag each Event with the event_type. Used when list has multiple types of events.

        :type old_userdb_format: bool
        :type mixed_format: bool

        :return: List of dicts
        :rtype: [dict]
        """
        return [this.to_dict(old_userdb_format=old_userdb_format,
                             mixed_format=mixed_format) for this in self._elements]


def event_from_dict(data, raise_on_unknown=True):
    """
    Create an Event instance (probably really a subclass of Event) from a dict.

    :param data: Password parameters from database
    :param raise_on_unknown: Raise EventHasUnknownData if unrecognized data is encountered

    :type data: dict
    :type raise_on_unknown: bool
    :rtype: Event
    """
    if not 'event_type' in data:
        raise UserDBValueError('No event type specified')
    if data['event_type'] == 'tou_event':
        from eduid_userdb.tou import ToUEvent  # avoid cyclic dependency by importing this here
        return ToUEvent(data=data, raise_on_unknown=raise_on_unknown)
    raise BadEvent('Unknown event_type in data: {!s}'.format(data['event_type']))
