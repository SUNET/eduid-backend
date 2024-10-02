from __future__ import annotations

from typing import Any

from pydantic import field_validator

from eduid.userdb.element import ElementKey, PrimaryElement, PrimaryElementList

__author__ = "ft"


class MailAddress(PrimaryElement):
    email: str

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, v: Any):
        if not isinstance(v, str):
            raise ValueError("must be a string")
        return v.lower()

    @property
    def key(self) -> ElementKey:
        """
        Return the element that is used as key for e-mail addresses in a PrimaryElementList.
        """
        return ElementKey(self.email)

    @classmethod
    def _from_dict_transform(cls: type[MailAddress], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if "csrf" in data:
            del data["csrf"]

        return data


class MailAddressList(PrimaryElementList[MailAddress]):
    """
    Hold a list of MailAddress instance.

    Provide methods to add, update and remove elements from the list while
    maintaining some governing principles, such as ensuring there is exactly
    one primary e-mail address in the list (except if the list is empty).
    """

    @classmethod
    def from_list_of_dicts(cls: type[MailAddressList], items: list[dict[str, Any]]) -> MailAddressList:
        return cls(elements=[MailAddress.from_dict(this) for this in items])


def address_from_dict(data: dict[str, Any]) -> MailAddress:
    """
    Create a MailAddress instance from a dict.

    :param data: Mail address parameters from database

    :type data: dict
    :rtype: MailAddress
    """
    return MailAddress.from_dict(data)
