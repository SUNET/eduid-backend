from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Union

from bson import ObjectId

from eduid.graphdb.exceptions import MultipleGroupsReturned, MultipleUsersReturned
from eduid.graphdb.groupdb.user import User
from eduid.graphdb.helpers import neo4j_ts_to_dt

__author__ = "lundberg"


@dataclass(frozen=True)
class Group:
    identifier: str
    display_name: str
    version: Optional[ObjectId] = None
    created_ts: Optional[datetime] = None
    modified_ts: Optional[datetime] = None
    owners: set[Union[User, Group]] = field(compare=False, default_factory=set)
    members: set[Union[User, Group]] = field(compare=False, default_factory=set)

    @staticmethod
    def _get_user(it: list[User], identifier: str) -> Optional[User]:
        res = [user for user in it if user.identifier == identifier]
        if not res:
            return None
        if len(res) != 1:
            raise MultipleUsersReturned(f"More than one user with identifier {identifier} found")
        return res[0]

    @staticmethod
    def _get_group(it: list[Group], identifier: str) -> Optional[Group]:
        res = [group for group in it if group.identifier == identifier]
        if not res:
            return None
        if len(res) != 1:
            raise MultipleGroupsReturned(f"More than one group with identifier {identifier} found")
        return res[0]

    @property
    def member_users(self) -> list[User]:
        return [item for item in self.members if isinstance(item, User)]

    @property
    def member_groups(self) -> list[Group]:
        return [item for item in self.members if isinstance(item, Group)]

    @property
    def owner_users(self) -> list[User]:
        return [item for item in self.owners if isinstance(item, User)]

    @property
    def owner_groups(self) -> list[Group]:
        return [item for item in self.owners if isinstance(item, Group)]

    def get_member_user(self, identifier: str) -> Optional[User]:
        return self._get_user(self.member_users, identifier=identifier)

    def get_owner_user(self, identifier: str) -> Optional[User]:
        return self._get_user(self.owner_users, identifier=identifier)

    def get_member_group(self, identifier: str) -> Optional[Group]:
        return self._get_group(self.member_groups, identifier=identifier)

    def get_owner_group(self, identifier: str) -> Optional[Group]:
        return self._get_group(self.owner_groups, identifier=identifier)

    def has_member(self, identifier: str) -> bool:
        return identifier in [member.identifier for member in self.members]

    def has_owner(self, identifier: str) -> bool:
        return identifier in [owner.identifier for owner in self.owners]

    @classmethod
    def from_mapping(cls, data: Mapping) -> Group:
        dt = neo4j_ts_to_dt(data)
        version = data.get("version")
        if version is not None:
            version = ObjectId(version)
        return cls(
            identifier=data["identifier"],
            version=version,
            display_name=data["display_name"],
            created_ts=dt["created_ts"],
            modified_ts=dt["modified_ts"],
            members=set(data.get("members", [])),
            owners=set(data.get("owners", [])),
        )
