# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Any, Dict, List, Type

from pydantic import Field, validator

from eduid.userdb.element import Element, ElementList
from eduid.userdb.exceptions import EduIDUserDBError

__author__ = 'lundberg'


class LockedIdentityElement(Element):

    """
    Element that is used to lock an identity to a user

    Properties of LockedIdentityElement:

        identity_type
    """

    identity_type: str

    @property
    def key(self) -> str:
        """
        :return: Type of identity
        """
        return self.identity_type


class LockedIdentityNin(LockedIdentityElement):

    """
    Element that is used to lock a NIN to a user

    Properties of LockedNinElement:

        number
    """

    number: str
    identity_type: str = 'nin'


class LockedIdentityList(ElementList[LockedIdentityElement]):
    """
    Hold a list of LockedIdentityElement instances.

    Provide methods to find and add to the list.
    """

    @classmethod
    def from_list_of_dicts(cls: Type[LockedIdentityList], items: List[Dict[str, Any]]) -> LockedIdentityList:
        return cls(elements=[LockedIdentityNin.from_dict(this) for this in items if this.get('identity_type') == 'nin'])

    def remove(self, key):
        """
        Override remove method as an element should be set once, remove never.
        """
        raise EduIDUserDBError('Removal of LockedIdentityElements is not permitted')
