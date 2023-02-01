from __future__ import annotations

from typing import Any, Mapping, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from eduid.common.misc.timeutil import utc_now

from eduid.userdb.db import TUserDbDocument
from eduid.userdb.user import User


class CacheUser(BaseModel):
    eppn: str
    created_ts: datetime = Field(default_factory=utc_now)
    next_run_ts: Optional[datetime] = None

    def to_dict(self) -> TUserDbDocument:
        """
        Convert Element to a dict in eduid format, that can be used to reconstruct the
        Element later.
        """
        data = self.dict(exclude_none=True)

        return TUserDbDocument(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CacheUser:
        """Convert a dict to a Element object."""
        return cls(**data)

    def from_user(self, data: User) -> CacheUser:
        """
        Convert a User object to a CacheUser object.
        """
        cache_user = CacheUser(
            eppn=data.eppn,
        )
        return cache_user
