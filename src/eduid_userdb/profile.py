# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime
from typing import Union, Optional, List, Any, Mapping

from eduid_userdb.element import Element, ElementList, DuplicateElementViolation
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


class Profile(Element):

    def __init__(self, owner: str, schema: str, profile_data: Mapping[str, Any],
                 created_by: Optional[str] = None, created_ts: Optional[Union[datetime, bool]] = None,
                 modified_ts: Optional[Union[datetime, bool]] = None):

        if created_ts is None:
            created_ts = True
        data = dict(created_by=created_by, created_ts=created_ts, modified_ts=modified_ts)
        super().__init__(data=data)

        self.owner = owner
        self.schema = schema
        self.profile_data = profile_data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Profile:
        return cls(**data)

    # -----------------------------------------------------------------
    @property
    def key(self) -> str:
        """
        Return the element that is used as key in a ElementList.
        """
        return self.owner

    # -----------------------------------------------------------------
    @property
    def owner(self) -> str:
        """
        This is the name of the profile owner.

        :return: Name of owner owner
        """
        return self._data['owner']

    @owner.setter
    def owner(self, value: str) -> None:
        """
        :param value: Name of owner owner
        """
        if not isinstance(value, str):
            raise UserDBValueError(f"Invalid 'owner': {repr(value)}")
        self._data['owner'] = value.lower()

    # -----------------------------------------------------------------
    @property
    def schema(self) -> str:
        """
        This is the schema used for the external data

        :return: Schema identifier
        """
        return self._data['schema']

    @schema.setter
    def schema(self, value: str) -> None:
        """
        :param value: Schema identifier
        """
        if not isinstance(value, str):
            raise UserDBValueError(f"Invalid 'schema': {repr(value)}")
        self._data['schema'] = value.lower()

    # -----------------------------------------------------------------
    @property
    def profile_data(self) -> Mapping[str, Any]:
        """
        This is the schema used for the external data

        :return: Schema identifier
        """
        return self._data['profile_data']

    @profile_data.setter
    def profile_data(self, value: Mapping[str, Any]) -> None:
        """
        :param value: Opaque profile data
        """
        if not isinstance(value, Mapping):
            raise UserDBValueError(f"Invalid 'profile_data': {repr(value)}")
        self._data['profile_data'] = value


class ProfileList(ElementList):
    """
    Hold a list of Profile instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is only one
    owner with the same name.

    :param profiles: List of profiles
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
    def from_list_of_dicts(cls, items: List[Mapping[str, Any]]) -> ProfileList:
        profiles = list()
        for item in items:
            profiles.append(Profile.from_dict(data=item))
        return cls(profiles=profiles)
