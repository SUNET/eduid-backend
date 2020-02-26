# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Union, Mapping, Type

__author__ = 'lundberg'

from eduid_groupdb.helpers import neo4j_ts_to_dt


@dataclass()
class User:
    identifier: str
    display_name: Optional[str] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None

    @classmethod
    def from_mapping(cls, data: Mapping) -> User:
        dt = neo4j_ts_to_dt(data)
        return cls(identifier=data['identifier'], display_name=data['display_name'],
                   created_ts=dt['created_ts'], modified_ts=dt['modified_ts'])


@dataclass()
class Group:
    scope: str
    identifier: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None
    owners: List[User] = field(default_factory=list)
    members: List[Union[User, Group]] = field(default_factory=list)

    def _filter_members(self, member_type: Type[Union[User, Group]]):
        return [member for member in self.members if isinstance(member, member_type)]

    @property
    def user_members(self) -> List[User]:
        return self._filter_members(member_type=User)

    @property
    def group_members(self) -> List[Group]:
        return self._filter_members(member_type=Group)

    @classmethod
    def from_mapping(cls, data: Mapping) -> Group:
        dt = neo4j_ts_to_dt(data)
        return cls(scope=data['scope'], identifier=data['identifier'], display_name=data['display_name'],
                   description=data['description'], created_ts=dt['created_ts'], modified_ts=dt['modified_ts'],
                   members=data.get('members', []), owners=data.get('owners', []))


