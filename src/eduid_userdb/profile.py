# -*- coding: utf-8 -*-

from __future__ import annotations

import copy
from datetime import datetime
from typing import Union, Optional, Mapping, List

from eduid_userdb.element import Element, ElementList, DuplicateElementViolation
from eduid_userdb.exceptions import UserDBValueError

__author__ = 'lundberg'


class Profile(Element):

    def __init__(self, owner: Optional[str] = None, schema: Optional[str] = None,
                 profile_data: Optional[Mapping] = None, application: Optional[str] = None,
                 created_ts: Optional[Union[datetime, bool]] = None, data: Optional[Mapping] = None):
        data_in = data
        data = copy.copy(data_in)  # to not modify callers data

        if data is None:
            if created_ts is None:
                created_ts = True
            data = dict(owner=owner,
                        schema=schema,
                        profile_data=profile_data,
                        created_by=application,
                        created_ts=created_ts,
                        )

        super(Profile, self).__init__(data=data)
        self.owner = data.pop('owner', None)
        self.schema = data.pop('schema', None)
        self.profile_data = data.pop('profile_data', None)

    @classmethod
    def from_dict(cls, data: Mapping) -> Profile:
        return cls(data=data)

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
    def profile_data(self) -> Mapping:
        """
        This is the schema used for the external data

        :return: Schema identifier
        """
        return self._data['profile_data']

    @profile_data.setter
    def profile_data(self, value: Mapping) -> None:
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
    def __init__(self, profiles: List[Union[Profile, Mapping]]):
        super(ProfileList, self).__init__(elements=list())

        for this in profiles:
            if isinstance(this, Profile):
                profile = this
            else:
                profile = Profile.from_dict(this)

            if self.find(profile.key):
                raise DuplicateElementViolation(f'Profile "{profile.key}" already in list')

            self.add(profile)

