# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Type

from pydantic import Field

from eduid.userdb.element import DuplicateElementViolation, Element, ElementList
from eduid.userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


class Profile(Element):
    owner: str
    profile_schema: str
    profile_data: Mapping[str, Any]

    @property
    def key(self) -> Optional[str]:
        """ Return the element that is used as key in a ElementList """
        return self.owner


class ProfileList(ElementList):
    """
    Hold a list of Profile instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is only one
    owner with the same name.
    """

    elements: List[Profile] = Field(default_factory=list)

    def _get_elements(self) -> List[Profile]:
        """
        This construct allows typing to infer the correct type of the elements
        when called from functions in the superclass.
        """
        return self.elements

    def old___init__(self, profiles: List[Profile]):
        super().__init__(elements=list())

        for profile in profiles:
            if not isinstance(profile, Profile):
                raise UserDBValueError(f"Instance not of type 'Profile': {repr(profile)}")

            if self.find(profile.key):
                raise DuplicateElementViolation(f'Profile "{profile.key}" already in list')

            self.add(profile)

    @classmethod
    def from_list_of_dicts(cls: Type[ProfileList], items: List[Dict[str, Any]]) -> ProfileList:
        return cls(elements=[Profile.from_dict(this) for this in items])
