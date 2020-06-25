# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Mapping, Optional, Union

from bson import ObjectId

from eduid_graphdb.exceptions import MultipleGroupsReturned, MultipleUsersReturned
from eduid_graphdb.groupdb.user import User
from eduid_graphdb.helpers import neo4j_ts_to_dt

__author__ = 'lundberg'


@dataclass()
class Group:
    identifier: str
    version: Optional[ObjectId] = None
    display_name: Optional[str] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None
    owners: List[Union[User, Group]] = field(default_factory=list)
    members: List[Union[User, Group]] = field(default_factory=list)

    def __eq__(self, other: object):
        if not isinstance(other, Group):
            return False
        return self.identifier == other.identifier

    def __hash__(self):
        # TODO: Hash has to include _all_ fields I think, definitely display_name. Probably owners and members.
        #       Maybe go with (eq=True, frozen=True)?
        return hash(self.identifier)

    @staticmethod
    def _get_user(it: List[User], identifier: str) -> Optional[User]:
        res = [user for user in it if user.identifier == identifier]
        if not res:
            return None
        if len(res) != 1:
            raise MultipleUsersReturned(f'More than one user with identifier {identifier} found')
        return res[0]

    @staticmethod
    def _get_group(it: List[Group], identifier: str) -> Optional[Group]:
        res = [group for group in it if group.identifier == identifier]
        if not res:
            return None
        if len(res) != 1:
            raise MultipleGroupsReturned(f'More than one group with identifier {identifier} found')
        return res[0]

    @property
    def member_users(self) -> List[User]:
        return [item for item in self.members if isinstance(item, User)]

    @property
    def member_groups(self) -> List[Group]:
        return [item for item in self.members if isinstance(item, Group)]

    @property
    def owner_users(self) -> List[User]:
        return [item for item in self.owners if isinstance(item, User)]

    @property
    def owner_groups(self) -> List[Group]:
        return [item for item in self.owners if isinstance(item, Group)]

    def get_member_user(self, identifier: str) -> Optional[User]:
        return self._get_user(self.member_users, identifier=identifier)

    def get_owner_user(self, identifier: str) -> Optional[User]:
        return self._get_user(self.owner_users, identifier=identifier)

    def get_member_group(self, identifier: str) -> Optional[Group]:
        return self._get_group(self.member_groups, identifier=identifier)

    def get_owner_group(self, identifier: str) -> Optional[Group]:
        return self._get_group(self.owner_groups, identifier=identifier)

    @classmethod
    def from_mapping(cls, data: Mapping) -> Group:
        dt = neo4j_ts_to_dt(data)
        version = data.get('version')
        if version is not None:
            version = ObjectId(version)
        return cls(
            identifier=data['identifier'],
            version=version,
            display_name=data['display_name'],
            created_ts=dt['created_ts'],
            modified_ts=dt['modified_ts'],
            members=data.get('members', []),
            owners=data.get('owners', []),
        )
