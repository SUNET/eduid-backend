from typing import Any, Mapping
from datetime import datetime
from pydantic import BaseModel, Field

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.meta import CleanerType


class Meta(BaseModel):
    periodicity: int
    cleaner_type: CleanerType
    created_ts: datetime = Field(default_factory=utc_now)

    def to_dict(self) -> TUserDbDocument:
        """
        Convert Element to a dict in eduid format, that can be used to reconstruct the
        Element later.
        """
        data = self.dict(exclude_none=True)

        return TUserDbDocument(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Meta":
        """Convert a dict to a Element object."""
        return cls(**data)
