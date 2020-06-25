# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Mapping, Optional

from eduid_graphdb.helpers import neo4j_ts_to_dt

__author__ = 'lundberg'


@dataclass()
class User:
    identifier: str
    display_name: Optional[str] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None

    def __eq__(self, other: object):
        if not isinstance(other, User):
            return False
        if self.identifier == other.identifier:
            return True
        return False

    def __hash__(self):
        return hash(self.identifier)

    @classmethod
    def from_mapping(cls, data: Mapping) -> User:
        dt = neo4j_ts_to_dt(data)
        return cls(
            identifier=data['identifier'],
            display_name=data['display_name'],
            created_ts=dt['created_ts'],
            modified_ts=dt['modified_ts'],
        )
