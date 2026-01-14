from __future__ import annotations

from typing import Any, Self

from eduid.userdb.element import ElementKey, PrimaryElement, PrimaryElementList

__author__ = "ft"


class PhoneNumber(PrimaryElement):
    """ """

    number: str

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key for phone numbers in a PrimaryElementList.
        """
        return ElementKey(self.number)

    @classmethod
    def _from_dict_transform(cls: type[PhoneNumber], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if "added_timestamp" in data:
            data["created_ts"] = data.pop("added_timestamp")

        if "mobile" in data:
            data["number"] = data.pop("mobile")

        if "csrf" in data:
            del data["csrf"]

        return data


class PhoneNumberList(PrimaryElementList[PhoneNumber]):
    """
    Hold a list of PhoneNumber instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary phone number in the list (except if the list is empty).
    """

    @classmethod
    def from_list_of_dicts(cls: type[Self], items: list[dict[str, Any]]) -> Self:
        return cls(elements=[PhoneNumber.from_dict(this) for this in items])
