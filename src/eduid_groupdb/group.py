# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import enum
from typing import Optional, List, Union, Mapping

__author__ = 'lundberg'


@enum.unique
class Role(enum.Enum):
    MEMBER = 'member'
    OWNER = 'owner'


@dataclass()
class User:
    identifier: str
    role: Role
    display_name: Optional[str] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: dict) -> User:
        #if 'created_ts' in data:
        #    data['created_ts'] = datetime.fromtimestamp(data['created_ts'])
        #if 'modified_ts' in data:
        #    data['modified_ts'] = datetime.fromtimestamp(data['modified_ts'])
        return cls(**data)


@dataclass()
class Group:
    scope: str
    identifier: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None
    members: List[Union[User, Group]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Mapping) -> Group:
        pass


