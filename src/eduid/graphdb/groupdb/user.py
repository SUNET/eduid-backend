from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

from eduid.graphdb.helpers import neo4j_ts_to_dt

__author__ = "lundberg"


@dataclass(frozen=True)
class User:
    identifier: str
    display_name: str
    created_ts: datetime | None = None
    modified_ts: datetime | None = None

    @classmethod
    def from_mapping(cls, data: Mapping) -> User:
        dt = neo4j_ts_to_dt(data)
        return cls(
            identifier=data["identifier"],
            display_name=data["display_name"],
            created_ts=dt["created_ts"],
            modified_ts=dt["modified_ts"],
        )
