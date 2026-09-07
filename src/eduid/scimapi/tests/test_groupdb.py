import logging
from collections.abc import Iterator
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from bson import ObjectId

from eduid.common.config.parsers import load_config
from eduid.common.misc.timeutil import utc_now
from eduid.graphdb.groupdb import Group as GraphGroup
from eduid.scimapi.config import ScimApiConfig
from eduid.scimapi.context import Context
from eduid.scimapi.testing import ScimApiTestCase
from eduid.userdb.scimapi import GroupExtensions, GroupMemberType, ScimApiGroup, ScimApiGroupDB, ScimApiGroupMember

logger = logging.getLogger(__name__)


def test_apply_members_owners_does_not_touch_neo4j_version() -> None:
    # Regression test: get_groups_for_user_identifer/get_groups_owned_by_user_identifier call
    # _apply_members_owners (not _hydrate_from_graph) precisely so that a bulk role-query's
    # potentially-stale version can never clobber the fresher _neo4j_version that
    # get_group_by_scim_id's own, more recent internal read already set on the same group object.
    group = ScimApiGroup(display_name="Test", members=set(), owners=set())
    group._neo4j_version = ObjectId("aaaaaaaaaaaaaaaaaaaaaaaa")
    graph = GraphGroup(
        identifier=str(group.scim_id), display_name="Test", version=ObjectId("bbbbbbbbbbbbbbbbbbbbbbbb")
    )

    ScimApiGroupDB._apply_members_owners(group, graph)
    assert group._neo4j_version == ObjectId("aaaaaaaaaaaaaaaaaaaaaaaa")

    ScimApiGroupDB._hydrate_from_graph(group, graph)
    assert group._neo4j_version == ObjectId("bbbbbbbbbbbbbbbbbbbbbbbb")


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
        # eduid.userdb.scimapi.basedb.scim_db_name (see doc/group-migration-neo4j-to-mongodb.md,
        # step 1c). The test config sets data_owners["eduid.se"].db_name = "eduid_se".
        assert self.groupdb is not None
        assert self.groupdb._coll_name == "eduid_se__groups"

    def test_indexes(self) -> None:
        # Test that all expected indexes are present (see doc/group-migration-neo4j-to-mongodb.md,
        # step 3 - Add the indexes).
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
        # created_ts/modified_ts must be excluded from ScimApiGroupMember comparison (and, since
        # the class is frozen, from __hash__ too) - see doc/group-migration-neo4j-to-mongodb.md,
        # step 2a. update_group's change-detection relies on set-equality, and a member whose
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
