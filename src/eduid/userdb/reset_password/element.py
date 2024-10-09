from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.element import Element, ElementKey


class CodeElement(Element):
    """ """

    code: str
    is_verified: bool

    @property
    def key(self) -> ElementKey:
        """Get element key."""
        return ElementKey(self.code)

    @classmethod
    def _from_dict_transform(cls: type[CodeElement], data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data received in eduid format into pythonic format.
        """
        data = super()._from_dict_transform(data)

        if "verified" in data:
            data["is_verified"] = data.pop("verified")

        return data

    def _to_dict_transform(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        if "is_verified" in data:
            data["verified"] = data.pop("is_verified")

        data = super()._to_dict_transform(data)

        return data

    def is_expired(self, timeout: timedelta) -> bool:
        """
        Check whether the code is expired.

        :param timeout_seconds: the number of seconds a code is valid
        """
        expiry_date = self.created_ts + timeout
        now = utc_now()
        return expiry_date < now

    @classmethod
    def parse(cls: type[CodeElement], code_or_element: Mapping | CodeElement | str, application: str) -> CodeElement:
        if isinstance(code_or_element, str):
            return cls(created_by=application, code=code_or_element, is_verified=False)
        if isinstance(code_or_element, dict):
            data = code_or_element
            for this in data.keys():
                if this not in [
                    "application",
                    "code",
                    "created_by",
                    "created_ts",
                    "verified",
                    "modified_ts",
                    "modified_by",
                ]:
                    raise ValueError(f"Unknown data {this} for CodeElement.parse from mapping")
            return cls(
                created_by=data.get("created_by", application),
                code=data["code"],
                created_ts=data.get("created_ts", utc_now()),
                is_verified=data.get("verified", False),
            )
        if isinstance(code_or_element, CodeElement):
            return code_or_element
        raise ValueError(f"Can't create CodeElement from input: {code_or_element}")
