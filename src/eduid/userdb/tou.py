from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Self

from bson import ObjectId
from pydantic import field_validator

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.event import Event, EventList
from eduid.userdb.exceptions import UserDBValueError


class ToUEvent(Event):
    """
    A record of a user's acceptance of a particular version of the Terms of Use.
    """

    created_by: str
    version: str

    @field_validator("version")
    @classmethod
    def _validate_tou_version(cls, v: object) -> str:
        if not v:
            raise ValueError("ToU must have a version")
        if not isinstance(v, str):
            raise TypeError("ToU version must be a string")
        return v

    @classmethod
    def _from_dict_transform(cls: type[ToUEvent], data: dict[str, Any]) -> dict[str, Any]:
        """ """
        data = super()._from_dict_transform(data)

        if "event_type" not in data:
            data["event_type"] = "tou_event"

        if "event_id" in data and isinstance(data["event_id"], ObjectId):
            data["event_id"] = str(data["event_id"])

        return data

    def is_expired(self, interval_seconds: int) -> bool:
        """
        Check whether the ToU event needs to be re-accepted.

        :param interval_seconds: the max number of seconds between a users acceptance of the ToU
        """
        if not isinstance(self.modified_ts, datetime):
            if self.modified_ts is None:
                return False
            raise UserDBValueError(f"Malformed modified_ts: {self.modified_ts!r}")
        delta = timedelta(seconds=interval_seconds)
        expiry_date = self.modified_ts + delta
        return expiry_date < utc_now()


class ToUList(EventList[ToUEvent]):
    """
    List of ToUEvents.

    TODO: Add, find and remove ought to operate on element.key and not element.version.
          has_accepted() is the interface to find an ToU event using a version number.
    """

    @classmethod
    def from_list_of_dicts(cls: type[Self], items: list[dict[str, Any]]) -> Self:
        return cls(elements=[ToUEvent.from_dict(this) for this in items])

    def has_accepted(self, version: str, reaccept_interval: int) -> bool:
        """
        Check if the user has accepted a particular version of the ToU.

        :param version: Version of ToU
        :param reaccept_interval: Time between accepting and the need to reaccept (default 3 years)
        """
        # All users have implicitly accepted the first ToU version (info stored in another collection)
        if version in ["2014-v1", "2014-dev-v1"]:
            return True
        for this in self.elements:
            if not isinstance(this, ToUEvent):
                raise UserDBValueError(f"Event {repr(this)} is not of type ToUEvent")

            if this.version == version and not this.is_expired(interval_seconds=reaccept_interval):
                return True
        return False
