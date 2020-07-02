# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Mapping, Optional

from eduid_graphdb.helpers import neo4j_ts_to_dt

__author__ = 'lundberg'


@dataclass(unsafe_hash=True)
class User:
    identifier: str
    display_name: str
    created_ts: Optional[datetime] = field(compare=False, default=None)
    modified_ts: Optional[datetime] = field(compare=False, default=None)

    @classmethod
    def from_mapping(cls, data: Mapping) -> User:
        dt = neo4j_ts_to_dt(data)
        return cls(
            identifier=data['identifier'],
            display_name=data['display_name'],
            created_ts=dt['created_ts'],
            modified_ts=dt['modified_ts'],
        )
