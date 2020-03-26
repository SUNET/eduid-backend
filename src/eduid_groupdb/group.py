# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Mapping, Optional, Type, Union

from bson import ObjectId

from eduid_groupdb.exceptions import MultipleUsersReturned, MultipleGroupsReturned
from eduid_groupdb.helpers import neo4j_ts_to_dt

__author__ = 'lundberg'


@dataclass()
class User:
    identifier: str
    display_name: Optional[str] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None

    def __eq__(self, other: object):
        if not isinstance(other, User):
            raise NotImplemented('other instance must be of type User')
        if self.identifier == other.identifier:
            return True
        return False

    @classmethod
    def from_mapping(cls, data: Mapping) -> User:
        dt = neo4j_ts_to_dt(data)
        return cls(
            identifier=data['identifier'],
            display_name=data['display_name'],
            created_ts=dt['created_ts'],
            modified_ts=dt['modified_ts'],
        )


@dataclass()
class Group:
    scope: str
    identifier: str
    version: Optional[ObjectId] = None
    display_name: Optional[str] = None
    description: Optional[str] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None
    owners: List[Union[User, Group]] = field(default_factory=list)
    members: List[Union[User, Group]] = field(default_factory=list)

    def __eq__(self, other: object):
        if not isinstance(other, Group):
            raise NotImplemented('other instance must be of type Group')
        if (self.scope == other.scope) and (self.identifier == other.identifier):
            return True
        return False

    @staticmethod
    def _filter_type(it: List[Union[User, Group]], member_type: Type[Union[User, Group]]):
        return [item for item in it if isinstance(item, member_type)]

    @staticmethod
    def _get_user(it: List[User], identifier: str) -> Optional[User]:
        res = [user for user in it if user.identifier == identifier]
        if not res:
            return None
        if len(res) != 1:
            raise MultipleUsersReturned(f'More than one user with identifier {identifier} found')
        return res[0]

    @staticmethod
    def _get_group(it: List[Group], scope: str, identifier: str) -> Optional[Group]:
        res = [group for group in it if group.scope == scope and group.identifier == identifier]
        if not res:
            return None
        if len(res) != 1:
            raise MultipleGroupsReturned(f'More than one group with scope {scope} and identifier {identifier} found')
        return res[0]

    @property
    def member_users(self) -> List[User]:
        return self._filter_type(it=self.members, member_type=User)

    @property
    def member_groups(self) -> List[Group]:
        return self._filter_type(it=self.members, member_type=Group)

    @property
    def owner_users(self) -> List[User]:
        return self._filter_type(it=self.owners, member_type=User)

    @property
    def owner_groups(self) -> List[Group]:
        return self._filter_type(it=self.owners, member_type=Group)

    def get_member_user(self, identifier: str):
        return self._get_user(self.member_users, identifier=identifier)

    def get_owner_user(self, identifier: str):
        return self._get_user(self.owner_users, identifier=identifier)

    def get_member_group(self, scope: str, identifier: str):
        return self._get_group(self.member_groups, scope=scope, identifier=identifier)

    def get_owner_group(self, scope: str, identifier: str):
        return self._get_group(self.owner_groups, scope=scope, identifier=identifier)

    @classmethod
    def from_mapping(cls, data: Mapping) -> Group:
        dt = neo4j_ts_to_dt(data)
        version = data.get('version')
        if version is not None:
            version = ObjectId(version)
        return cls(
            scope=data['scope'],
            identifier=data['identifier'],
            version=version,
            display_name=data['display_name'],
            description=data['description'],
            created_ts=dt['created_ts'],
            modified_ts=dt['modified_ts'],
            members=data.get('members', []),
            owners=data.get('owners', []),
        )
