import logging
from collections.abc import Iterator
from dataclasses import replace
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from pymongo.errors import PyMongoError
from pytest_mock import MockerFixture

from eduid.common.config.parsers import load_config
from eduid.common.misc.timeutil import utc_now
from eduid.graphdb.groupdb import Group as GraphGroup
from eduid.graphdb.groupdb import User as GraphUser
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.testing import ScimApiTestCase
from eduid.userdb.scimapi import GroupExtensions, GroupMemberType, ScimApiGroup, ScimApiGroupDB, ScimApiGroupMember

logger = logging.getLogger(__name__)


def test_group_to_dict_from_dict_roundtrip() -> None:
    # members/owners must round-trip through to_dict()/from_dict() correctly, including a
    # member with created_ts set and one with no timestamps at all.
    now = utc_now()
    member_with_ts = ScimApiGroupMember(
        identifier=str(uuid4()), display_name="Member With Ts", member_type=GroupMemberType.USER, created_ts=now
    )
    member_without_ts = ScimApiGroupMember(
        identifier=str(uuid4()), display_name="Member Without Ts", member_type=GroupMemberType.GROUP
    )
    owner = ScimApiGroupMember(identifier=str(uuid4()), display_name="Owner", member_type=GroupMemberType.USER)
    group = ScimApiGroup(
        display_name="Round Trip Group",
        members={member_with_ts, member_without_ts},
        owners={owner},
    )

    doc = group.to_dict()
    assert doc.get("members") is not None
    assert doc.get("owners") is not None

    reloaded = ScimApiGroup.from_dict(doc)
    # ScimApiGroupMember equality (and hash) ignores timestamps, so this compares
    # identifier/display_name/member_type only - exactly what the round trip must preserve.
    assert reloaded.members == group.members
    assert reloaded.owners == group.owners

    # Timestamps are excluded from ScimApiGroupMember equality, so the assertions above alone
    # would still pass even if _member_from_doc dropped or corrupted created_ts/modified_ts -
    # check those explicitly too.
    assert reloaded.members is not None
    reloaded_with_ts = next(m for m in reloaded.members if m.identifier == member_with_ts.identifier)
    reloaded_without_ts = next(m for m in reloaded.members if m.identifier == member_without_ts.identifier)
    assert reloaded_with_ts.created_ts == now
    assert reloaded_without_ts.created_ts is None
    assert reloaded_without_ts.modified_ts is None


def test_group_from_dict_absent_members_owners_is_none() -> None:
    # Regression test for the "not yet migrated" sentinel (section 1.1): a mongodb document
    # with no members/owners key at all (the pre-cutover shape) must parse to members=None,
    # owners=None - never set().
    group = ScimApiGroup(display_name="Fresh From Mongo", members=set(), owners=set())
    doc = group.to_dict()
    del doc["members"]
    del doc["owners"]
    reloaded = ScimApiGroup.from_dict(doc)
    assert reloaded.members is None
    assert reloaded.owners is None


class TestGroupDB(ScimApiTestCase):
    @pytest.fixture(autouse=True)
    def setup(self, scimapi_setup: None) -> Iterator[None]:
        self.test_config = self._get_config()
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        self.context = Context(config=config)
        self.groupdb = self.context.get_groupdb("eduid.se")

        for i in range(9):
            self.add_group(uuid4(), f"Test Group-{i}")

        yield

        assert self.groupdb is not None
        self.groupdb._drop_whole_collection()

    def add_group(self, scim_id: UUID, display_name: str, extensions: GroupExtensions | None = None) -> ScimApiGroup:
        if extensions is None:
            extensions = GroupExtensions()
        group = ScimApiGroup(
            scim_id=scim_id, display_name=display_name, extensions=extensions, members=set(), owners=set()
        )
        assert self.groupdb  # mypy doesn't know setUp will be called
        self.groupdb.save(group)
        logger.info(f"TEST saved group {group}")
        return group

    def test_collection_name(self) -> None:
        # Regression test for the collection-name derivation consolidated in
        # eduid.userdb.scimapi.basedb.scim_db_name. The test config sets
        # data_owners["eduid.se"].db_name = "eduid_se".
        assert self.groupdb is not None
        assert self.groupdb._coll_name == "eduid_se__groups"

    def test_indexes(self) -> None:
        # Test that all expected indexes are present.
        assert self.groupdb is not None
        assert set(self.groupdb._coll.index_information()) == {
            "_id_",
            "unique-scimid",
            "members-identifier",
            "owners-identifier",
            "display-name",
            "last-modified",
        }

    def test_full_search(self) -> None:
        assert self.groupdb is not None
        groups = self.groupdb.get_groups()
        assert len(groups) == 9

    def test_documents_and_count_first_page(self) -> None:
        assert self.groupdb is not None
        groups, count = self.groupdb._get_documents_and_count_by_filter(spec={}, limit=3)
        for x in groups:
            logger.info(f"Group {x}")
        assert len(groups) == 3
        assert count == 9

    def test_documents_and_count_last_page(self) -> None:
        assert self.groupdb is not None
        groups, count = self.groupdb._get_documents_and_count_by_filter(spec={}, skip=6, limit=3)
        assert len(groups) == 3
        assert count == 9

    def test_documents_and_count_partial_last_page(self) -> None:
        assert self.groupdb is not None
        groups, count = self.groupdb._get_documents_and_count_by_filter(spec={}, skip=8, limit=3)
        assert len(groups) == 1
        assert count == 9

    def test_members_mutated_in_place_are_saved(self) -> None:
        # Regression test for an invariant scimapi/routers/utils/users.py relies on: it mutates
        # group.members in place (e.g. `.remove(member)`) and then calls save() on that same
        # group object, trusting that the in-place mutation is what gets persisted.
        assert self.groupdb is not None
        group = self.add_group(uuid4(), "Test Group Mutate In Place")
        member = ScimApiGroupMember(identifier=str(uuid4()), display_name="Some User", member_type=GroupMemberType.USER)

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        assert loaded.members is not None
        loaded.members.add(member)
        self.groupdb.save(loaded)

        reloaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert reloaded is not None
        assert reloaded.members == {member}

        assert loaded.members is not None
        loaded.members.remove(member)
        self.groupdb.save(loaded)

        reloaded_again = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert reloaded_again is not None
        assert reloaded_again.members == set()

    def test_group_member_equality_ignores_timestamps(self) -> None:
        # created_ts/modified_ts must be excluded from ScimApiGroupMember comparison (and,
        # since the class is frozen, from __hash__ too). update_group's change-detection relies
        # on set-equality, and a member whose
        # timestamp was merely refreshed must not look like a changed member.
        now = utc_now()
        member1 = ScimApiGroupMember(
            identifier="test-identifier",
            display_name="Test User",
            member_type=GroupMemberType.USER,
            created_ts=now,
            modified_ts=None,
        )
        member2 = ScimApiGroupMember(
            identifier="test-identifier",
            display_name="Test User",
            member_type=GroupMemberType.USER,
            created_ts=now + timedelta(seconds=1),
            modified_ts=now,
        )
        assert member1 == member2
        assert hash(member1) == hash(member2)
        assert len({member1, member2}) == 1

    def test_save_raises_on_unhydrated_members(self) -> None:
        # section 4.4: save() must refuse to persist a group whose members is None (never
        # hydrated/migrated), since that would silently un-migrate it.
        assert self.groupdb is not None
        group = ScimApiGroup(display_name="Unhydrated Members", owners=set())
        assert group.members is None
        with pytest.raises(RuntimeError):
            self.groupdb.save(group)

    def test_save_raises_on_unhydrated_owners(self) -> None:
        assert self.groupdb is not None
        group = ScimApiGroup(display_name="Unhydrated Owners", members=set())
        assert group.owners is None
        with pytest.raises(RuntimeError):
            self.groupdb.save(group)

    def test_save_raises_on_truncated_members(self) -> None:
        # section 4.4: save() must refuse to persist a role-truncated group (e.g. one returned
        # by get_groups_for_user_identifer for role MEMBER), since persisting it would delete
        # every other member of the group.
        assert self.groupdb is not None
        group = ScimApiGroup(display_name="Truncated", members=set(), owners=set(), members_truncated=True)
        with pytest.raises(RuntimeError):
            self.groupdb.save(group)

    def test_save_merges_member_timestamps(self) -> None:
        # section 4.4: save() must reimplement neo4j's ON CREATE SET r.created_ts /
        # ON MATCH SET r.modified_ts semantics - an unchanged member keeps created_ts and a
        # None modified_ts; a member whose display_name changed keeps created_ts but gets a
        # fresh modified_ts.
        assert self.groupdb is not None
        member = ScimApiGroupMember(
            identifier=str(uuid4()), display_name="Stable Member", member_type=GroupMemberType.USER
        )
        group = ScimApiGroup(display_name="Timestamp Merge Group", members={member}, owners=set())
        self.groupdb.save(group)

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        assert loaded.members is not None
        first_saved = next(iter(loaded.members))
        assert first_saved.created_ts is not None
        assert first_saved.modified_ts is None

        # Re-save with the exact same, unchanged member - created_ts stable, modified_ts still None.
        self.groupdb.save(loaded)
        reloaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert reloaded is not None
        assert reloaded.members is not None
        second_saved = next(iter(reloaded.members))
        assert second_saved.created_ts == first_saved.created_ts
        assert second_saved.modified_ts is None

        # Change the member's display_name and save again - modified_ts is now set, created_ts
        # is still unchanged from the very first save.
        changed_member = next(iter(reloaded.members))
        reloaded.members = {replace(changed_member, display_name="Renamed Member")}
        self.groupdb.save(reloaded)

        final = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert final is not None
        assert final.members is not None
        final_member = next(iter(final.members))
        assert final_member.created_ts == first_saved.created_ts
        assert final_member.modified_ts is not None

    def test_get_groups_by_last_modified_returns_hydrated_groups(self) -> None:
        # section 4.3: get_groups_by_last_modified must hydrate members/owners like every
        # other read path - it used to return un-hydrated groups.
        assert self.groupdb is not None
        groups, count = self.groupdb.get_groups_by_last_modified(operator="gt", value=utc_now() - timedelta(days=1))
        assert count == 9
        for group in groups:
            assert group.members is not None
            assert group.owners is not None


class TestGroupMigrateOnRead(ScimApiTestCase):
    @pytest.fixture(autouse=True)
    def setup(self, scimapi_setup: None) -> Iterator[None]:
        self.test_config = self._get_config()
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        self.context = Context(config=config)
        self.groupdb = self.context.get_groupdb("eduid.se")
        assert self.groupdb is not None

        yield

        self.groupdb._drop_whole_collection()

    def _add_unmigrated_group(
        self, display_name: str = "Unmigrated Group", with_neo4j_data: bool = True
    ) -> ScimApiGroup:
        """
        Save a group the normal way (mongo-only - migrated by construction), then strip
        members/owners from its stored document to simulate a pre-cutover, not-yet-migrated
        group, and optionally seed a corresponding neo4j node with real members/owners.
        """
        assert self.groupdb is not None
        group = ScimApiGroup(display_name=display_name, members=set(), owners=set())
        self.groupdb.save(group)
        self.groupdb._coll.update_one({"_id": group.group_id}, {"$unset": {"members": "", "owners": ""}})
        if with_neo4j_data:
            assert self.groupdb.graphdb is not None
            self.groupdb.graphdb.save(
                GraphGroup(
                    identifier=str(group.scim_id),
                    display_name=display_name,
                    members={GraphUser(identifier=str(uuid4()), display_name="Member 1")},
                    owners={GraphUser(identifier=str(uuid4()), display_name="Owner 1")},
                )
            )
        return group

    def test_migrate_on_read_populates_members_and_owners(self) -> None:
        assert self.groupdb is not None
        group = self._add_unmigrated_group()
        raw_before = self.groupdb._coll.find_one({"_id": group.group_id})
        assert raw_before is not None
        assert "members" not in raw_before
        assert "owners" not in raw_before

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        assert loaded.members is not None
        assert len(loaded.members) == 1
        assert loaded.owners is not None
        assert len(loaded.owners) == 1

        raw_after = self.groupdb._coll.find_one({"_id": group.group_id})
        assert raw_after is not None
        assert "members" in raw_after
        assert "owners" in raw_after
        # Non-negotiable: the migrating read must never touch version/last_modified.
        assert raw_after["version"] == raw_before["version"]
        assert raw_after["last_modified"] == raw_before["last_modified"]

    def test_migrate_on_read_only_hits_neo4j_once(self, mocker: MockerFixture) -> None:
        assert self.groupdb is not None
        group = self._add_unmigrated_group()
        first = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert first is not None

        assert self.groupdb.graphdb is not None
        spy = mocker.patch.object(self.groupdb.graphdb, "get_group")
        second = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert second is not None
        spy.assert_not_called()

    def test_migrate_on_read_survives_concurrent_migration_race(self, mocker: MockerFixture) -> None:
        assert self.groupdb is not None
        group = self._add_unmigrated_group()
        mocker.patch.object(self.groupdb._coll, "update_one", return_value=mocker.MagicMock(modified_count=0))

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        assert loaded.members is not None
        assert len(loaded.members) == 1
        assert loaded.owners is not None
        assert len(loaded.owners) == 1

    def test_migrate_on_read_reloads_winning_document_after_lost_race(self, mocker: MockerFixture) -> None:
        # Regression test: when _migrate_group's own update_one loses its compare-and-set
        # because a concurrent save() (or migration) already won, that winning mongodb document
        # may already disagree with the neo4j snapshot this call read - e.g. a member removed by
        # that concurrent save(). Returning the stale neo4j-derived value as-is would resurrect
        # that membership, which is exactly what this migration must not do, especially on the
        # reverse-lookup union path. It must reload and return the winning document instead.
        assert self.groupdb is not None
        group = self._add_unmigrated_group()  # neo4j has 1 member, 1 owner; mongo has neither yet
        real_update_one = self.groupdb._coll.update_one

        def losing_update_one(*args: object, **kwargs: object) -> Any:  # noqa: ANN401
            # Simulate a concurrent winner making exactly this write for real (removing the
            # member), then report our own attempt as having lost the race.
            real_update_one({"_id": group.group_id}, {"$set": {"members": [], "owners": []}})
            return mocker.MagicMock(modified_count=0)

        mocker.patch.object(self.groupdb._coll, "update_one", side_effect=losing_update_one)

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        # Must reflect the winning document (empty), not the stale neo4j snapshot (1 member/1 owner).
        assert loaded.members == set()
        assert loaded.owners == set()

    def test_migrate_on_read_survives_mongodb_write_failure(self, mocker: MockerFixture) -> None:
        assert self.groupdb is not None
        group = self._add_unmigrated_group()
        # _migrate_group's guard is scoped to PyMongoError specifically (not a bare Exception),
        # so a real mongo failure is what this must simulate.
        mocker.patch.object(self.groupdb._coll, "update_one", side_effect=PyMongoError("boom"))

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        assert loaded.members is not None
        assert len(loaded.members) == 1
        assert loaded.owners is not None
        assert len(loaded.owners) == 1

    def test_migrate_on_read_empty_neo4j_group(self) -> None:
        assert self.groupdb is not None
        group = self._add_unmigrated_group(with_neo4j_data=False)
        assert self.groupdb.graphdb is not None
        self.groupdb.graphdb.save(GraphGroup(identifier=str(group.scim_id), display_name=group.display_name))

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        assert loaded.members == set()
        assert loaded.owners == set()

        # An empty result still counts as migrated: members/owners are present (as []), not absent.
        raw = self.groupdb._coll.find_one({"_id": group.group_id})
        assert raw is not None
        assert raw["members"] == []
        assert raw["owners"] == []

    def test_migrate_on_read_no_neo4j_node(self) -> None:
        assert self.groupdb is not None
        group = self._add_unmigrated_group(with_neo4j_data=False)

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        assert loaded.members == set()
        assert loaded.owners == set()


class TestGroupReverseLookup(ScimApiTestCase):
    """
    Tests for the mongodb+neo4j union reverse lookup implemented in
    ScimApiGroupDB._get_groups_for_role, and for remove_group's tolerance of a neo4j delete
    failure.
    """

    @pytest.fixture(autouse=True)
    def setup(self, scimapi_setup: None) -> Iterator[None]:
        self.test_config = self._get_config()
        config = load_config(typ=ScimApiConfig, app_name="scimapi", ns="api", test_config=self.test_config)
        self.context = Context(config=config)
        self.groupdb = self.context.get_groupdb("eduid.se")
        assert self.groupdb is not None

        yield

        self.groupdb._drop_whole_collection()

    def _save_group(
        self,
        display_name: str,
        members: set[ScimApiGroupMember] | None = None,
        owners: set[ScimApiGroupMember] | None = None,
    ) -> ScimApiGroup:
        assert self.groupdb is not None
        group = ScimApiGroup(
            display_name=display_name,
            members=members if members is not None else set(),
            owners=owners if owners is not None else set(),
        )
        self.groupdb.save(group)
        return group

    def _make_unmigrated(
        self,
        group: ScimApiGroup,
        members: set[ScimApiGroupMember] | None = None,
        owners: set[ScimApiGroupMember] | None = None,
    ) -> None:
        """
        Strip members/owners from a group's mongodb document (simulating a not-yet-migrated,
        pre-cutover document) and seed the corresponding neo4j node/edges directly, bypassing
        ScimApiGroupDB.save() entirely (which no longer writes neo4j from the cutover on).
        """
        assert self.groupdb is not None
        self.groupdb._coll.update_one({"_id": group.group_id}, {"$unset": {"members": "", "owners": ""}})
        assert self.groupdb.graphdb is not None
        self.groupdb.graphdb.save(
            GraphGroup(
                identifier=str(group.scim_id),
                display_name=group.display_name,
                members={GraphUser(identifier=m.identifier, display_name=m.display_name) for m in (members or set())},
                owners={GraphUser(identifier=o.identifier, display_name=o.display_name) for o in (owners or set())},
            )
        )

    def test_migrated_group_found_via_mongodb_leg_without_neo4j_migration_read(self, mocker: MockerFixture) -> None:
        # A migrated group (created via save() as usual) with a member must be found via the
        # mongodb leg. The neo4j leg still runs as part of the union (graphdb is configured),
        # but the more expensive migration read (graphdb.get_group) must not be triggered for a
        # group that mongodb already answered for.
        assert self.groupdb is not None
        member_id = str(uuid4())
        member = ScimApiGroupMember(identifier=member_id, display_name="Member", member_type=GroupMemberType.USER)
        group = self._save_group("Migrated With Member", members={member})

        assert self.groupdb.graphdb is not None
        spy_lookup = mocker.spy(self.groupdb.graphdb, "get_groups_for_user_identifer")
        spy_migrate = mocker.spy(self.groupdb.graphdb, "get_group")

        found = self.groupdb.get_groups_for_user_identifer(UUID(member_id))

        assert {str(g.scim_id) for g in found} == {str(group.scim_id)}
        spy_lookup.assert_called_once()
        spy_migrate.assert_not_called()

    def test_removed_member_not_resurrected_by_stale_neo4j_edge(self) -> None:
        # A migrated group from which a member was removed via save() must not be "resurrected"
        # by its still-present (now stale) neo4j edge - nothing deletes neo4j edges any more
        # once a group is migrated, since save() no longer writes neo4j at all.
        assert self.groupdb is not None
        member_id = str(uuid4())
        member = ScimApiGroupMember(identifier=member_id, display_name="Member", member_type=GroupMemberType.USER)
        group = self._save_group("Migrated Then Member Removed", members={member})

        assert self.groupdb.graphdb is not None
        self.groupdb.graphdb.save(
            GraphGroup(
                identifier=str(group.scim_id),
                display_name=group.display_name,
                members={GraphUser(identifier=member_id, display_name="Member")},
            )
        )

        loaded = self.groupdb.get_group_by_scim_id(str(group.scim_id))
        assert loaded is not None
        assert loaded.members is not None
        loaded.members.clear()
        self.groupdb.save(loaded)

        assert self.groupdb.get_groups_for_user_identifer(UUID(member_id)) == []

    def test_unmigrated_group_found_via_neo4j_leg_and_migrated_as_side_effect(self) -> None:
        assert self.groupdb is not None
        member_id = str(uuid4())
        owner_id = str(uuid4())
        member = ScimApiGroupMember(identifier=member_id, display_name="Member", member_type=GroupMemberType.USER)
        owner = ScimApiGroupMember(identifier=owner_id, display_name="Owner", member_type=GroupMemberType.USER)
        group = self._save_group("Unmigrated")
        self._make_unmigrated(group, members={member}, owners={owner})

        member_result = self.groupdb.get_groups_for_user_identifer(UUID(member_id))
        assert {str(g.scim_id) for g in member_result} == {str(group.scim_id)}

        owner_result = self.groupdb.get_groups_owned_by_user_identifier(UUID(owner_id))
        assert {str(g.scim_id) for g in owner_result} == {str(group.scim_id)}

        raw = self.groupdb._coll.find_one({"_id": group.group_id})
        assert raw is not None
        assert raw.get("members") is not None
        assert raw.get("owners") is not None

    def test_neo4j_only_group_with_no_mongodb_doc_is_skipped_silently(self) -> None:
        assert self.groupdb is not None
        assert self.groupdb.graphdb is not None
        identifier = str(uuid4())
        self.groupdb.graphdb.save(
            GraphGroup(
                identifier=str(uuid4()),
                display_name="Orphan",
                members={GraphUser(identifier=identifier, display_name="Member")},
                owners={GraphUser(identifier=identifier, display_name="Member")},
            )
        )

        assert self.groupdb.get_groups_for_user_identifer(UUID(identifier)) == []
        assert self.groupdb.get_groups_owned_by_user_identifier(UUID(identifier)) == []

    @pytest.mark.parametrize("migrated", [True, False])
    def test_asymmetry_preserved_regardless_of_which_leg_answers(self, migrated: bool) -> None:
        # owner={A}, members={A, B, C}: get_groups_for_user_identifer(B) must return exactly
        # {B} as members (truncated) and {A} (full) as owners; get_groups_owned_by_user_identifier(A)
        # must return the full {A, B, C} as members and {A} as owners. This asymmetry is an
        # authorization boundary (see webapp/group_management/helpers.py) and must hold whether
        # mongodb or neo4j answered.
        assert self.groupdb is not None
        owner_a = str(uuid4())
        member_b = str(uuid4())
        member_c = str(uuid4())
        members = {
            ScimApiGroupMember(identifier=owner_a, display_name="A", member_type=GroupMemberType.USER),
            ScimApiGroupMember(identifier=member_b, display_name="B", member_type=GroupMemberType.USER),
            ScimApiGroupMember(identifier=member_c, display_name="C", member_type=GroupMemberType.USER),
        }
        owners = {ScimApiGroupMember(identifier=owner_a, display_name="A", member_type=GroupMemberType.USER)}

        if migrated:
            group = self._save_group("Asymmetry", members=members, owners=owners)
        else:
            group = self._save_group("Asymmetry")
            self._make_unmigrated(group, members=members, owners=owners)

        member_result = self.groupdb.get_groups_for_user_identifer(UUID(member_b))
        assert len(member_result) == 1
        found_as_member = member_result[0]
        assert {m.identifier for m in (found_as_member.members or set())} == {member_b}
        assert {o.identifier for o in (found_as_member.owners or set())} == {owner_a}

        owner_result = self.groupdb.get_groups_owned_by_user_identifier(UUID(owner_a))
        assert len(owner_result) == 1
        found_as_owner = owner_result[0]
        assert {m.identifier for m in (found_as_owner.members or set())} == {owner_a, member_b, member_c}
        assert {o.identifier for o in (found_as_owner.owners or set())} == {owner_a}

    def test_neo4j_fallback_false_hides_unmigrated_groups(self) -> None:
        # Documents the precondition for eventually flipping neo4j_fallback to false for good:
        # with the fallback off, a not-yet-migrated group is invisible to both reverse-lookup
        # methods - no exception, just absent from the result.
        assert self.groupdb is not None
        member_id = str(uuid4())
        member = ScimApiGroupMember(identifier=member_id, display_name="Member", member_type=GroupMemberType.USER)
        group = self._save_group("Unmigrated Hidden")
        self._make_unmigrated(group, members={member})

        # Deliberately not closed: BaseDB/MongoClientCache shares one pymongo client per
        # connection URI across every db instance in the test process (including self.groupdb),
        # so closing it here would break every other test sharing the same mongo instance.
        no_fallback_db = ScimApiGroupDB(
            scope=self.groupdb.scope,
            mongo_uri=self.test_config["mongo_uri"],
            mongo_dbname="eduid_scimapi",
            mongo_collection=self.groupdb._coll_name,
            neo4j_uri=self.test_config.get("neo4j_uri"),
            neo4j_config=self.test_config.get("neo4j_config"),
            neo4j_fallback=False,
            setup_indexes=False,
        )
        assert no_fallback_db.graphdb is None
        assert no_fallback_db.get_groups_for_user_identifer(UUID(member_id)) == []
        assert no_fallback_db.get_groups_owned_by_user_identifier(UUID(member_id)) == []

    def test_remove_group_tolerates_neo4j_delete_failure(self, mocker: MockerFixture) -> None:
        assert self.groupdb is not None
        group = self._save_group("To Be Removed")
        assert self.groupdb.graphdb is not None
        mocker.patch.object(self.groupdb.graphdb, "remove_group", side_effect=RuntimeError("neo4j down"))

        assert self.groupdb.remove_group(group) is True
        assert self.groupdb._coll.find_one({"_id": group.group_id}) is None
