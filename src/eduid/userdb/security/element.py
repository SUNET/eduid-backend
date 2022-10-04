# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict

from pydantic import Field

from eduid.userdb.element import Element, ElementKey


class CodeElement(Element):
    """ """

    code: str
    is_verified: bool = Field(default=False, alias="verified")

    @property
    def key(self) -> ElementKey:
        """Get element key."""
        return ElementKey(self.code)

    def _to_dict_transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform data kept in pythonic format into eduid format.
        """
        if "is_verified" in data:
            data["verified"] = data.pop("is_verified")

        data = super()._to_dict_transform(data)

        return data

    def is_expired(self, timeout_seconds: int) -> bool:
        """
        Check whether the code is expired.

        :param timeout_seconds: the number of seconds a code is valid
        """
        delta = timedelta(seconds=timeout_seconds)
        expiry_date = self.created_ts + delta
        now = datetime.now(tz=self.created_ts.tzinfo)
        return expiry_date < now
