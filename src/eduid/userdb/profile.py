# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Type

from pydantic import Field, validator

from eduid.userdb.element import Element, ElementList

__author__ = 'lundberg'


class Profile(Element):
    owner: str
    profile_schema: str
    profile_data: Mapping[str, Any]

    @property
    def key(self) -> Optional[str]:
        """ Return the element that is used as key in a ElementList """
        return self.owner


class ProfileList(ElementList[Profile]):
    """
    Hold a list of Profile instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is only one
    owner with the same name.
    """

    @classmethod
    def from_list_of_dicts(cls: Type[ProfileList], items: List[Dict[str, Any]]) -> ProfileList:
        return cls(elements=[Profile.from_dict(this) for this in items])
