from __future__ import annotations

from typing import Any

from pydantic import field_validator

from eduid.userdb.element import ElementKey
from eduid.userdb.exceptions import EduIDUserDBError
from eduid.userdb.identity import IdentityElement, IdentityList

__author__ = "lundberg"


class LockedIdentityList(IdentityList):
    """
    Hold a list of IdentityElement instances.
    """

    @field_validator("elements")
    @classmethod
    def validate_is_verified(cls, v: list[IdentityElement]):
        # If using a validator with a subclass that references a List type field on a parent class, using
        # each_item=True will cause the validator not to run; instead, the list must be iterated over programmatically.
        if not all([item.is_verified for item in v]):
            raise ValueError("Locked identity has to be verified")
        return v

    @classmethod
    def from_list_of_dicts(cls: type[LockedIdentityList], items: list[dict[str, Any]]) -> LockedIdentityList:
        obj = super().from_list_of_dicts(items=items)
        return cls(elements=obj.elements)

    def replace(self, element: IdentityElement) -> None:
        self.elements = [this for this in self.elements if this.key != element.key]
        self.add(element=element)
        return None

    def remove(self, key: ElementKey):
        """
        Override remove method as an element should be set once, remove never.
        """
        raise EduIDUserDBError("Removal of IdentityElements from LockedIdentityList is not permitted")
