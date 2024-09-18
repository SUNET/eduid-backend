from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from eduid.userdb.element import Element, ElementKey, ElementList

__author__ = "lundberg"


class Profile(Element):
    owner: str
    profile_schema: str
    profile_data: Mapping[str, Any]

    @property
    def key(self) -> ElementKey:
        """Return the element that is used as key in a ElementList"""
        return ElementKey(self.owner)


class ProfileList(ElementList[Profile]):
    """
    Hold a list of Profile instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is only one
    owner with the same name.
    """

    @classmethod
    def from_list_of_dicts(cls: type[ProfileList], items: list[dict[str, Any]]) -> ProfileList:
        return cls(elements=[Profile.from_dict(this) for this in items])
