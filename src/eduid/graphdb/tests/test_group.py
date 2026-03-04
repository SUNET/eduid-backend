from typing import NotRequired, TypedDict
from unittest import TestCase

from eduid.graphdb.groupdb import Group, User

__author__ = "lundberg"


class GroupData(TypedDict):
    identifier: str
    display_name: str
    members: NotRequired[set[Group | User]]
    owners: NotRequired[set[Group | User]]


class UserData(TypedDict):
    identifier: str
    display_name: str


class TestGroup(TestCase):
    def setUp(self) -> None:
        self.group1: GroupData = {
            "identifier": "test1",
            "display_name": "Test Group 1",
        }
        self.group2: GroupData = {
            "identifier": "test2",
            "display_name": "Test Group 2",
        }
        self.user1: UserData = {"identifier": "user1", "display_name": "Test Testsson"}
        self.user2: UserData = {"identifier": "user2", "display_name": "Namn Namnsson"}

    def test_init_group(self) -> None:
        group = Group(**self.group1)
        assert self.group1["identifier"] == group.identifier
        assert self.group1["display_name"] == group.display_name

    def test_init_group_with_members(self) -> None:
        user = User(**self.user1)
        self.group1["members"] = {user}
        group = Group(**self.group1)
        assert user in group.members
        assert user in group.member_users
        assert len(group.member_groups) == 0
        group.members.add(Group(**self.group2))
        assert len(group.member_groups) == 1
        group.members.add(User(**self.user2))
        assert len(group.members) == 3

    def test_init_group_with_owner_and_member(self) -> None:
        user = User(**self.user1)
        owner = User(**self.user2)
        self.group1["members"] = {user}
        self.group1["owners"] = {owner}
        group = Group(**self.group1)
        assert user in group.members
        assert user in group.member_users
        assert owner in group.owners

    def test_get_users_and_groups(self) -> None:
        member1 = User(**self.user1)
        member2 = User(**self.user2)
        member3 = Group(**self.group2)
        owner1 = User(**self.user1)
        owner2 = User(**self.user2)
        owner3 = Group(**self.group2)

        self.group1["members"] = {member1, member2, member3}
        self.group1["owners"] = {owner1, owner2, owner3}
        group = Group(**self.group1)

        assert owner2 == group.get_owner_user(identifier=owner2.identifier)
        assert member2 == group.get_member_user(identifier=member2.identifier)
        assert owner3 == group.get_owner_group(identifier=owner3.identifier)
        assert member3 == group.get_member_group(identifier=member3.identifier)

        assert group.get_member_user(identifier="missing_identifier") is None
        assert group.get_owner_user(identifier="missing_identifier") is None
        assert group.get_member_group(identifier="missing_identifier") is None
        assert group.get_owner_group(identifier="missing_identifier") is None
