from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Optional

from eduid.graphdb.helpers import neo4j_ts_to_dt

__author__ = "lundberg"


@dataclass(frozen=True)
class User:
    identifier: str
    display_name: str
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None

    @classmethod
    def from_mapping(cls, data: Mapping) -> User:
        dt = neo4j_ts_to_dt(data)
        return cls(
            identifier=data["identifier"],
            display_name=data["display_name"],
            created_ts=dt["created_ts"],
            modified_ts=dt["modified_ts"],
        )
