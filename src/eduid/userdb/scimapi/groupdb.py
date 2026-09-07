from __future__ import annotations

import copy
import logging
import pprint
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from enum import StrEnum, unique
from typing import Any, Self
from uuid import UUID

from bson import ObjectId

from eduid.common.misc.timeutil import utc_now
from eduid.graphdb.groupdb import Group as GraphGroup
from eduid.graphdb.groupdb import GroupDB
from eduid.graphdb.groupdb import User as GraphUser
from eduid.scimapi.models.group import GroupCreateRequest, GroupUpdateRequest
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.exceptions import DocumentOutOfSync
from eduid.userdb.scimapi.basedb import ScimApiBaseDB
from eduid.userdb.scimapi.common import ScimApiResourceBase

__author__ = "lundberg"

logger = logging.getLogger(__name__)


@dataclass
class GroupExtensions:
    data: dict[str, Any] = field(default_factory=dict)  # arbitrary third party data

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_mapping(cls: type[Self], data: Mapping[str, Any]) -> Self:
        return cls(
            data=data.get("data", {}),
        )


@unique
class GroupMemberType(StrEnum):
    USER = "user"
    GROUP = "group"


@dataclass(frozen=True)
class ScimApiGroupMember:
    """
    A group member or owner, either a user or another group.

    created_ts/modified_ts are intentionally excluded from comparison (and therefore from
    __hash__, since the class is frozen): update_group's change-detection relies on
    set-equality between the old and new member sets, and a member whose timestamp was
    merely refreshed must not look like a "changed" member.
    """

    identifier: str
    display_name: str
    member_type: GroupMemberType
    created_ts: datetime | None = field(default=None, compare=False)
    modified_ts: datetime | None = field(default=None, compare=False)


@dataclass
class _ScimApiGroupRequired:
    display_name: str


@dataclass
class ScimApiGroup(ScimApiResourceBase, _ScimApiGroupRequired):
    group_id: ObjectId = field(default_factory=ObjectId)
    extensions: GroupExtensions = field(default_factory=GroupExtensions)
    # None means "not loaded" (e.g. a group freshly parsed from a mongodb document, before
    # members/owners have been hydrated from neo4j). An empty set means "loaded, and empty".
    # Excluded from comparison/hash, matching how GraphGroup.members/owners worked before.
    members: set[ScimApiGroupMember] | None = field(default=None, compare=False)
    owners: set[ScimApiGroupMember] | None = field(default=None, compare=False)
    # Set on groups returned by the role-truncated reverse lookups (get_groups_for_user_identifer),
    # where neo4j only returns the querying entity as a member, not the full membership. Not
    # persisted. A guardrail for a later step, where save() will refuse to persist such a group.
    members_truncated: bool = field(default=False, compare=False, repr=False)
    # The neo4j Group node's version, as of the last time members/owners were hydrated from
    # neo4j. Not persisted to mongodb - neo4j is still the only store for members/owners.
    # Used by _to_graph_group() to give graphdb.save()'s optimistic-concurrency MERGE a version
    # that actually matches the node this group was read from, instead of re-reading neo4j for
    # the current version immediately before every write (which would make that check a no-op).
    _neo4j_version: ObjectId | None = field(default=None, compare=False, repr=False)

    @property
    def member_users(self) -> list[ScimApiGroupMember]:
        return [m for m in (self.members or set()) if m.member_type is GroupMemberType.USER]

    @property
    def member_groups(self) -> list[ScimApiGroupMember]:
        return [m for m in (self.members or set()) if m.member_type is GroupMemberType.GROUP]

    @property
    def owner_users(self) -> list[ScimApiGroupMember]:
        return [m for m in (self.owners or set()) if m.member_type is GroupMemberType.USER]

    @property
    def owner_groups(self) -> list[ScimApiGroupMember]:
        return [m for m in (self.owners or set()) if m.member_type is GroupMemberType.GROUP]

    @staticmethod
    def _first_with_identifier(items: list[ScimApiGroupMember], identifier: str) -> ScimApiGroupMember | None:
        for item in items:
            if item.identifier == identifier:
                return item
        return None

    def get_member_user(self, identifier: str) -> ScimApiGroupMember | None:
        return self._first_with_identifier(self.member_users, identifier)

    def get_member_group(self, identifier: str) -> ScimApiGroupMember | None:
        return self._first_with_identifier(self.member_groups, identifier)

    def add_member(self, member: ScimApiGroupMember) -> None:
        if self.members is None:
            self.members = set()
        self.members.add(member)

    def add_owner(self, owner: ScimApiGroupMember) -> None:
        if self.owners is None:
            self.owners = set()
        self.owners.add(owner)

    def has_member(self, identifier: UUID) -> bool:
        return str(identifier) in {m.identifier for m in (self.members or set())}

    def has_owner(self, identifier: UUID) -> bool:
        return str(identifier) in {o.identifier for o in (self.owners or set())}

    def to_dict(self) -> TUserDbDocument:
        # members/owners are not persisted yet - neo4j is still the only store for them.
        # members_truncated and _neo4j_version are runtime-only bookkeeping, never persisted.
        # Cleared here, before asdict(), rather than popped from its result afterwards - asdict()
        # deep-copies every field it recurses into, and a populated members/owners set can be
        # large (see doc/group-migration-neo4j-to-mongodb.md, R8), so this avoids deep-copying it
        # only to immediately discard the copy.
        res = asdict(replace(self, members=None, owners=None, members_truncated=False, _neo4j_version=None))
        res["scim_id"] = str(res["scim_id"])
        res["_id"] = res.pop("group_id")
        res.pop("members", None)
        res.pop("owners", None)
        res.pop("members_truncated", None)
        res.pop("_neo4j_version", None)
        return TUserDbDocument(res)

    @classmethod
    def from_dict(cls: type[Self], data: Mapping[str, Any]) -> Self:
        this = dict(copy.copy(data))  # to not modify callers data
        this["scim_id"] = uuid.UUID(this["scim_id"])
        this["group_id"] = this.pop("_id")
        this["extensions"] = GroupExtensions.from_mapping(this["extensions"])
        # members/owners are never present in a mongodb document yet (to_dict never writes
        # them), so this is always None here - never default to set(), see the migration doc.
        this.setdefault("members", None)
        this.setdefault("owners", None)
        return cls(**this)


def _member_to_graph_node(member: ScimApiGroupMember) -> GraphUser | GraphGroup:
    if member.member_type is GroupMemberType.GROUP:
        return GraphGroup(identifier=member.identifier, display_name=member.display_name)
    return GraphUser(identifier=member.identifier, display_name=member.display_name)


def _member_from_graph_node(node: GraphUser | GraphGroup) -> ScimApiGroupMember:
    member_type = GroupMemberType.GROUP if isinstance(node, GraphGroup) else GroupMemberType.USER
    return ScimApiGroupMember(
        identifier=node.identifier,
        display_name=node.display_name,
        member_type=member_type,
        created_ts=node.created_ts,
        modified_ts=node.modified_ts,
    )


class ScimApiGroupDB(ScimApiBaseDB):
    def __init__(
        self,
        neo4j_uri: str,
        scope: str,
        mongo_uri: str,
        mongo_dbname: str,
        mongo_collection: str,
        neo4j_config: dict[str, Any] | None = None,
        setup_indexes: bool = True,
    ) -> None:
        super().__init__(mongo_uri, mongo_dbname, collection=mongo_collection)
        # scope is kept here directly (in addition to self.graphdb.scope), since it needs to
        # survive the eventual removal of graphdb - see doc/group-migration-neo4j-to-mongodb.md.
        self.scope = scope
        self.graphdb = GroupDB(db_uri=neo4j_uri, scope=scope, config=neo4j_config)
        logger.info(f"{self} initialised")

        # Create an index so that scim_id is unique per data owner
        indexes = {
            "unique-scimid": {"key": [("scim_id", 1)], "unique": True},
            "members-identifier": {"key": [("members.identifier", 1)]},
            "owners-identifier": {"key": [("owners.identifier", 1)]},
            "display-name": {"key": [("display_name", 1)]},
            "last-modified": {"key": [("last_modified", 1)]},
        }
        if setup_indexes:
            self.setup_indexes(indexes)

    def _get_graph_group(self, scim_id: str) -> GraphGroup:
        graph_group = self.graphdb.get_group(scim_id)
        if graph_group is None:
            raise RuntimeError(f"Group {scim_id} found in mongodb, but not in graphdb")
        return graph_group

    def _to_graph_group(self, group: ScimApiGroup) -> GraphGroup:
        """
        Convert a ScimApiGroup's members/owners into a real GraphGroup, ready to write to neo4j.

        Uses group._neo4j_version - the version captured the last time this group was hydrated
        from neo4j - rather than reading neo4j fresh right before the write. Re-reading here
        would make graphdb.save()'s optimistic-concurrency MERGE always match whatever is
        currently in neo4j, i.e. a no-op check, and would cost an extra neo4j round trip on
        every save(). A freshly constructed group (never hydrated) has _neo4j_version=None,
        which graphdb.save() treats as "create".
        """
        return GraphGroup(
            identifier=str(group.scim_id),
            display_name=group.display_name,
            version=group._neo4j_version,
            members={_member_to_graph_node(m) for m in (group.members or set())},
            owners={_member_to_graph_node(m) for m in (group.owners or set())},
        )

    @staticmethod
    def _apply_members_owners(group: ScimApiGroup, graph: GraphGroup) -> None:
        group.members = {_member_from_graph_node(m) for m in graph.members}
        group.owners = {_member_from_graph_node(o) for o in graph.owners}

    @classmethod
    def _hydrate_from_graph(cls, group: ScimApiGroup, graph: GraphGroup) -> None:
        cls._apply_members_owners(group, graph)
        group._neo4j_version = graph.version

    def save(self, group: ScimApiGroup) -> bool:
        group_dict = group.to_dict()

        test_doc = {
            "_id": group.group_id,
            "version": group.version,
        }
        # update the version number and last_modified timestamp
        group_dict["version"] = ObjectId()
        group_dict["last_modified"] = utc_now()
        result = self._coll.replace_one(test_doc, group_dict, upsert=False)
        if result.modified_count == 0:
            db_group = self._coll.find_one({"_id": group.group_id})
            if db_group:
                logger.debug(f"{self} FAILED Updating group {group} in {self._coll_name}")
                raise DocumentOutOfSync("Group out of sync, please retry")
            self._coll.insert_one(group_dict)
        # Save graphdb group
        # TODO: Should we try to roll back mongodb change if the graphdb save fails?
        saved_graph_group = self.graphdb.save(self._to_graph_group(group))
        self._hydrate_from_graph(group, saved_graph_group)

        # put the new version number and last_modified in the group object after a successful update
        group.version = group_dict["version"]
        group.last_modified = group_dict["last_modified"]
        logger.debug(f"{self} Updated group {group} in {self._coll_name}")

        extra_debug = pprint.pformat(group_dict, width=120)
        logger.debug(f"Extra debug:\n{extra_debug}")

        return result.acknowledged

    def create_group(self, create_request: GroupCreateRequest) -> ScimApiGroup:
        extension_data = {}
        if create_request.nutid_group_v1 is not None:
            extension_data = create_request.nutid_group_v1.data
        group = ScimApiGroup(
            external_id=create_request.external_id,
            extensions=GroupExtensions(data=extension_data),
            display_name=create_request.display_name,
            members=set(),
            owners=set(),
        )
        if not self.save(group):
            logger.error(f"Creating group {group} failed")
            raise RuntimeError("Group creation failed")
        return group

    def update_group(self, update_request: GroupUpdateRequest, db_group: ScimApiGroup) -> tuple[ScimApiGroup, bool]:
        changed = False
        updated_members: set[ScimApiGroupMember] = set()
        logger.info(f"Updating group {db_group.scim_id!s}")
        # please mypy
        _member: ScimApiGroupMember | None
        _new_member: ScimApiGroupMember | None

        for this in update_request.members:
            if this.is_user:
                _member = db_group.get_member_user(identifier=str(this.value))
                _new_member = (
                    None
                    if _member
                    else ScimApiGroupMember(
                        identifier=str(this.value), display_name=this.display, member_type=GroupMemberType.USER
                    )
                )
            elif this.is_group:
                _member = db_group.get_member_group(identifier=str(this.value))
                _new_member = (
                    None
                    if _member
                    else ScimApiGroupMember(
                        identifier=str(this.value), display_name=this.display, member_type=GroupMemberType.GROUP
                    )
                )
            else:
                raise ValueError(f"Don't recognise member {this}")

            # Add a new member
            if _new_member is not None:
                updated_members.add(_new_member)
                logger.debug(f"Added new member: {_new_member}")
            # Update member attributes if they changed
            elif _member is not None and _member.display_name != this.display:
                logger.debug(f"Changed display name for existing member: {_member.display_name} -> {this.display}")
                _member = replace(_member, display_name=this.display)
                updated_members.add(_member)
            elif _member is not None:
                # no change, retain member as-is
                updated_members.add(_member)

        if db_group.display_name != update_request.display_name:
            changed = True
            logger.debug(f"Changed display name for group: {db_group.display_name} -> {update_request.display_name}")
            db_group.display_name = update_request.display_name

        if db_group.external_id != update_request.external_id:
            changed = True
            db_group.external_id = update_request.external_id
            logger.debug(f"Changed external id for group: {db_group.external_id} -> {update_request.external_id}")

        # Check if there were new, changed or removed members
        if db_group.members != updated_members:
            changed = True
            logger.debug(f"Old members: {db_group.members}")
            logger.debug(f"New members: {updated_members}")
            db_group.members = updated_members

        extension_data = {}
        if update_request.nutid_group_v1 is not None:
            extension_data = update_request.nutid_group_v1.data
        _sg_ext = GroupExtensions(data=extension_data)
        if db_group.extensions != _sg_ext:
            changed = True
            db_group.extensions = _sg_ext
            logger.debug(f"Old extensions: {db_group.extensions}")
            logger.debug(f"New extensions: {_sg_ext}")

        if changed:
            logger.info(f"Group {db_group.scim_id!s} changed. Saving.")
            if self.save(db_group):
                logger.info(f"Group {db_group.scim_id!s} saved.")
            else:
                logger.warning(f"Update of group {db_group} probably failed")

        return db_group, changed

    def get_groups(self) -> list[ScimApiGroup]:
        docs = self._get_documents_by_filter({})
        res: list[ScimApiGroup] = []
        for doc in docs:
            group = ScimApiGroup.from_dict(doc)
            self._hydrate_from_graph(group, self._get_graph_group(str(group.scim_id)))
            res += [group]
        return res

    def get_group_by_scim_id(self, scim_id: str) -> ScimApiGroup | None:
        doc = self._get_document_by_attr("scim_id", scim_id)
        if doc:
            group = ScimApiGroup.from_dict(doc)
            self._hydrate_from_graph(group, self._get_graph_group(scim_id))
            return group
        return None

    def get_group_by_display_name(self, display_name: str) -> ScimApiGroup | None:
        doc = self._get_document_by_attr("display_name", display_name)
        if doc:
            group = ScimApiGroup.from_dict(doc)
            self._hydrate_from_graph(group, self._get_graph_group(str(group.scim_id)))
            return group
        return None

    def get_groups_by_property(
        self, key: str, value: str | int, skip: int = 0, limit: int = 100
    ) -> tuple[list[ScimApiGroup], int]:
        docs, count = self._get_documents_and_count_by_filter({key: value}, skip=skip, limit=limit)
        if not docs:
            return [], 0
        res: list[ScimApiGroup] = []
        for this in docs:
            group = ScimApiGroup.from_dict(this)
            self._hydrate_from_graph(group, self._get_graph_group(str(group.scim_id)))
            res += [group]
        return res, count

    def get_groups_for_user_identifer(self, member_identifier: UUID) -> list[ScimApiGroup]:
        groups = self.graphdb.get_groups_for_user_identifer(str(member_identifier))
        res: list[ScimApiGroup] = []
        for graph in groups:
            group = self.get_group_by_scim_id(graph.identifier)
            if not group:
                raise RuntimeError(f"Group {graph} found in graph database, but not in mongodb")
            # neo4j already truncated members to just the querying entity for role MEMBER -
            # use that result instead of the full member list get_group_by_scim_id fetched, and
            # flag the group as truncated so a later step's save() guard can refuse to persist it.
            # Only members/owners come from this truncated `graph` - get_group_by_scim_id just
            # above already hydrated group._neo4j_version from its own, more recent read, and
            # overwriting it with this bulk query's (potentially older) version would give any
            # subsequent save() a stale version to hand to neo4j's optimistic-concurrency check.
            self._apply_members_owners(group, graph)
            group.members_truncated = True
            res += [group]
        return res

    def get_groups_owned_by_user_identifier(self, owner_identifier: UUID) -> list[ScimApiGroup]:
        groups = self.graphdb.get_groups_owned_by_user_identifier(str(owner_identifier))
        res: list[ScimApiGroup] = []
        for graph in groups:
            group = self.get_group_by_scim_id(graph.identifier)
            if not group:
                raise RuntimeError(f"Group {graph} found in graph database, but not in mongodb")
            # neo4j does not truncate members for role OWNER, so this is the full member list.
            # See get_groups_for_user_identifer above for why _neo4j_version must not be touched
            # here.
            self._apply_members_owners(group, graph)
            res += [group]
        return res

    def get_groups_by_last_modified(
        self, operator: str, value: datetime, limit: int | None = None, skip: int | None = None
    ) -> tuple[list[ScimApiGroup], int]:
        mongo_operator = self._get_mongo_operator(operator)
        spec = {"last_modified": {mongo_operator: value}}
        docs, total_count = self._get_documents_and_count_by_filter(spec=spec, limit=limit, skip=skip)
        groups = [ScimApiGroup.from_dict(x) for x in docs]
        return groups, total_count

    def group_exists(self, scim_id: str) -> bool:
        return bool(self.db_count(spec={"scim_id": scim_id}, limit=1))

    def remove_group(self, group: ScimApiGroup) -> bool:
        if not self.remove_document(group.group_id):
            return False
        self.graphdb.remove_group(str(group.scim_id))
        return True
