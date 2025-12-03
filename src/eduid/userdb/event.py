from __future__ import annotations

from abc import ABC
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from pydantic import Field

from eduid.userdb.element import Element, ElementKey, ElementList
from eduid.userdb.exceptions import BadEvent, UserDBValueError

if TYPE_CHECKING:
    from eduid.userdb.tou import ToUEvent


class Event(Element):
    """ """

    data: dict[str, Any] | None = None
    event_type: str | None = None
    event_id: str = Field(default_factory=lambda: str(uuid4()), alias="id")
    # This is a short-term hack to deploy new dataclass based events without
    # any changes to data in the production database. Remove after a burn-in period.
    no_event_type_in_db: bool = False

    @property
    def key(self) -> ElementKey:
        """Return the element that is used as key for events in an ElementList."""
        return ElementKey(self.event_id)

    @classmethod
    def _from_dict_transform(cls: type[Event], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if "event_type" not in data:
            data["no_event_type_in_db"] = True  # Remove this line when Event.no_event_type_in_db is removed

        if "id" in data:
            data["event_id"] = data.pop("id")

        return data

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        data = super()._to_dict_transform(data)

        # If there was no event_type in the data that was loaded from the database,
        # don't write one back if it matches the implied one of 'tou_event'
        if "no_event_type_in_db" in data:
            if data.pop("no_event_type_in_db") is True:
                if "event_type" in data:
                    del data["event_type"]

        return data


class EventList[ListElement: Element](ElementList[ListElement], ABC):
    """
    Hold a list of Event instances.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there no duplicates in the list.
    """


def event_from_dict(data: dict[str, Any]) -> ToUEvent:
    """
    Create an Event instance (probably really a subclass of Event) from a dict.

    :param data: Password parameters from database
    """
    if "event_type" not in data:
        raise UserDBValueError("No event type specified")
    if data["event_type"] == "tou_event":
        from eduid.userdb.tou import ToUEvent  # avoid cyclic dependency by importing this here

        return ToUEvent.from_dict(data=data)
    raise BadEvent("Unknown event_type in data: {!s}".format(data["event_type"]))
