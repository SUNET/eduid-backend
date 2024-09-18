from unittest import TestCase

from eduid.graphdb.groupdb import Group, User

__author__ = "lundberg"


class TestGroup(TestCase):
    def setUp(self) -> None:
        self.group1: dict[str, str | list] = {
            "identifier": "test1",
            "display_name": "Test Group 1",
        }
        self.group2: dict[str, str | list] = {
            "identifier": "test2",
            "display_name": "Test Group 2",
        }
        self.user1: dict[str, str] = {"identifier": "user1", "display_name": "Test Testsson"}
        self.user2: dict[str, str] = {"identifier": "user2", "display_name": "Namn Namnsson"}

    def test_init_group(self):
        group = Group(**self.group1)
        assert self.group1["identifier"] == group.identifier
        assert self.group1["display_name"] == group.display_name

    def test_init_group_with_members(self):
        user = User(**self.user1)
        self.group1["members"] = [user]
        group = Group(**self.group1)
        assert user in group.members
        assert user in group.member_users
        assert 0 == len(group.member_groups)
        group.members.append(Group(**self.group2))
        assert 1 == len(group.member_groups)
        group.members.append(User(**self.user2))
        assert 3 == len(group.members)

    def test_init_group_with_owner_and_member(self):
        user = User(**self.user1)
        owner = User(**self.user2)
        self.group1["members"] = [user]
        self.group1["owners"] = [owner]
        group = Group(**self.group1)
        assert user in group.members
        assert user in group.member_users
        assert owner in group.owners

    def test_get_users_and_groups(self):
        member1 = User(**self.user1)
        member2 = User(**self.user2)
        member3 = Group(**self.group2)
        owner1 = User(**self.user1)
        owner2 = User(**self.user2)
        owner3 = Group(**self.group2)

        self.group1["members"] = [member1, member2, member3]
        self.group1["owners"] = [owner1, owner2, owner3]
        group = Group(**self.group1)

        assert owner2 == group.get_owner_user(identifier=owner2.identifier)
        assert member2 == group.get_member_user(identifier=member2.identifier)
        assert owner3 == group.get_owner_group(identifier=owner3.identifier)
        assert member3 == group.get_member_group(identifier=member3.identifier)

        assert group.get_member_user(identifier="missing_identifier") is None
        assert group.get_owner_user(identifier="missing_identifier") is None
        assert group.get_member_group(identifier="missing_identifier") is None
        assert group.get_owner_group(identifier="missing_identifier") is None
