# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import Any, Dict, List, Type

from pydantic import validator

from eduid.userdb.exceptions import EduIDUserDBError
from eduid.userdb.identity import IdentityElement, IdentityList

__author__ = 'lundberg'


class LockedIdentityList(IdentityList):
    """
    Hold a list of IdentityElement instances.
    """

    @validator('elements', each_item=True)
    def verify_validated(cls, v: IdentityElement):
        if not v.is_verified:
            raise ValueError('Locked identity has to be verified')
        return v

    @classmethod
    def from_list_of_dicts(cls: Type[LockedIdentityList], items: List[Dict[str, Any]]) -> LockedIdentityList:
        obj = super().from_list_of_dicts(items=items)
        return cls(elements=obj.elements)

    def remove(self, key):
        """
        Override remove method as an element should be set once, remove never.
        """
        raise EduIDUserDBError('Removal of IdentityElements from LockedIdentityList is not permitted')
