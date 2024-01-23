from __future__ import annotations

from typing import Any

from eduid.userdb.element import ElementKey, PrimaryElement, PrimaryElementList

__author__ = "ft"


class Nin(PrimaryElement):
    """ """

    number: str

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key for nin numbers in a PrimaryElementList.
        """
        return ElementKey(self.number)


class NinList(PrimaryElementList[Nin]):
    """
    Hold a list of Nin instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary nin number in the list (except if the list is empty).
    """

    @classmethod
    def from_list_of_dicts(cls: type[NinList], items: list[dict[str, Any]]) -> NinList:
        return cls(elements=[Nin.from_dict(this) for this in items])


def nin_from_dict(data: dict[str, Any]) -> Nin:
    """
    Create a Nin instance from a dict.
    """
    return Nin.from_dict(data)
