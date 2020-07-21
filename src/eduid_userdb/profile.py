# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

from eduid_userdb.element import DuplicateElementViolation, Element, ElementList
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


@dataclass
class Profile(Element):
    """
    """
    owner: Optional[str] = None
    schema: Optional[str] = None
    profile_data: Optional[Mapping[str, Any]] = None

    @property
    def key(self) -> str:
        """ Return the element that is used as key in a ElementList """
        return self.owner


class ProfileList(ElementList):
    """
    Hold a list of Profile instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is only one
    owner with the same name.
    """

    def __init__(self, profiles: List[Profile]):
        super().__init__(elements=list())

        for profile in profiles:
            if not isinstance(profile, Profile):
                raise UserDBValueError(f"Instance not of type 'Profile': {repr(profile)}")

            if self.find(profile.key):
                raise DuplicateElementViolation(f'Profile "{profile.key}" already in list')

            self.add(profile)

    @classmethod
    def from_list_of_dicts(cls, items: List[Dict[str, Any]]) -> ProfileList:
        profiles = list()
        for item in items:
            profiles.append(Profile.from_dict(item))
        return cls(profiles=profiles)
