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
from pymongo.errors import PyMongoError

from eduid.common.misc.timeutil import utc_now
from eduid.graphdb.groupdb import Group as GraphGroup
from eduid.graphdb.groupdb import GroupDB
from eduid.graphdb.groupdb import User as GraphUser
from eduid.scimapi.models.group import GroupCreateRequest, GroupUpdateRequest
from eduid.userdb.db import TUserDbDocument
from eduid.userdb.exceptions import DocumentOutOfSync
from eduid.userdb.group_management import GroupRole
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
    # None means "not yet migrated to mongodb" (a group whose members/owners have never been
    # read from - and written back from - neo4j). An empty set means "migrated, and empty".
    # Absence, not an explicit marker, is what mongodb uses to tell the two states apart, so
    # this must never default to set(). Excluded from comparison/hash, matching how
    # GraphGroup.members/owners worked before.
    members: set[ScimApiGroupMember] | None = field(default=None, compare=False)
    owners: set[ScimApiGroupMember] | None = field(default=None, compare=False)
    # Set on groups returned by the role-truncated reverse lookups (get_groups_for_user_identifer),
    # where neo4j only returns the querying entity as a member, not the full membership. Not
    # persisted. A guardrail: save() refuses to persist such a group.
    members_truncated: bool = field(default=False, compare=False, repr=False)

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
        # members/owners are cleared here, before asdict(), rather than popped from its result
        # afterwards - asdict() deep-copies every field it recurses into, and a populated
        # members/owners set can be large, so this avoids deep-copying it only to immediately
        # discard the copy. members_truncated is a plain bool (no deep-copy cost either way)
        # and is always popped below regardless.
        res = asdict(replace(self, members=None, owners=None))
        res["scim_id"] = str(res["scim_id"])
        res["_id"] = res.pop("group_id")
        res.pop("members_truncated", None)
        res.pop("members", None)
        res.pop("owners", None)
        # Present (even []) means migrated; absent means not yet migrated - never write null.
        if self.members is not None:
            res["members"] = _serialize_members(self.members)
        if self.owners is not None:
            res["owners"] = _serialize_members(self.owners)
        return TUserDbDocument(res)

    @classmethod
    def from_dict(cls: type[Self], data: Mapping[str, Any]) -> Self:
        this = dict(copy.copy(data))  # to not modify callers data
        this["scim_id"] = uuid.UUID(this["scim_id"])
        this["group_id"] = this.pop("_id")
        this["extensions"] = GroupExtensions.from_mapping(this["extensions"])
        # Absent key => None (not yet migrated); present (even []) => a real, migrated value.
        # Must never default to set().
        this["members"] = _members_from_docs(this.get("members"))
        this["owners"] = _members_from_docs(this.get("owners"))
        return cls(**this)


def _member_sort_key(member: ScimApiGroupMember) -> tuple[str, str]:
    # Sorting members/owners before writing them makes stored documents deterministic.
    return member.member_type.value, member.identifier


def _serialize_members(members: set[ScimApiGroupMember]) -> list[dict[str, Any]]:
    return [
        {
            "identifier": m.identifier,
            "display_name": m.display_name,
            # Explicit .value rather than relying on GroupMemberType's StrEnum-ness to encode
            # itself as a plain string in bson - avoids a subtle pymongo encoding surprise.
            "member_type": m.member_type.value,
            "created_ts": m.created_ts,
            "modified_ts": m.modified_ts,
        }
        for m in sorted(members, key=_member_sort_key)
    ]


def _member_from_doc(data: Mapping[str, Any]) -> ScimApiGroupMember:
    return ScimApiGroupMember(
        identifier=data["identifier"],
        display_name=data["display_name"],
        member_type=GroupMemberType(data["member_type"]),
        created_ts=data.get("created_ts"),
        modified_ts=data.get("modified_ts"),
    )


def _members_from_docs(data: Any) -> set[ScimApiGroupMember] | None:  # noqa: ANN401
    if data is None:
        return None
    return {_member_from_doc(m) for m in data}


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
        scope: str,
        mongo_uri: str,
        mongo_dbname: str,
        mongo_collection: str,
        neo4j_uri: str | None = None,
        neo4j_config: dict[str, Any] | None = None,
        neo4j_fallback: bool = True,
        setup_indexes: bool = True,
    ) -> None:
        super().__init__(mongo_uri, mongo_dbname, collection=mongo_collection)
        # scope is kept here directly (in addition to self.graphdb.scope), since it needs to
        # survive the eventual removal of graphdb.
        self.scope = scope
        # mongodb is the sole write target for members/owners; neo4j is only ever consulted as
        # a read-only fallback for a group that has not been migrated to mongodb yet. graphdb
        # is therefore optional: neo4j_fallback=False, or no neo4j_uri configured, means no
        # neo4j connection is opened at all.
        self.graphdb: GroupDB | None = (
            # Truthy, not `is not None` - an explicitly-empty neo4j_uri="" is not a valid bolt
            # URI either, and GroupDB(db_uri="") raises ValueError("db_uri not supplied")
            # rather than behaving like "no neo4j configured".
            GroupDB(db_uri=neo4j_uri, scope=scope, config=neo4j_config)
            if neo4j_fallback and neo4j_uri
            else None
        )
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

    @staticmethod
    def _members_owners_from_graph(graph: GraphGroup) -> tuple[set[ScimApiGroupMember], set[ScimApiGroupMember]]:
        """Convert a neo4j GraphGroup's members/owners into ScimApiGroupMember sets. Read-only."""
        members = {_member_from_graph_node(m) for m in graph.members}
        owners = {_member_from_graph_node(o) for o in graph.owners}
        return members, owners

    def _load_group(self, doc: TUserDbDocument) -> ScimApiGroup:
        """
        Build a ScimApiGroup from a mongodb document, migrating it on read from neo4j if it
        has not been migrated yet.
        """
        group = ScimApiGroup.from_dict(doc)
        if group.members is not None and group.owners is not None:
            # Already migrated - mongodb is the whole truth, no neo4j read needed.
            return group
        if self.graphdb is None:
            # Fallback disabled (or never configured) and this group was never migrated.
            # Treat it as an empty, migrated group rather than crashing every read forever.
            logger.warning(f"Group {group.scim_id} has no members/owners in mongodb and neo4j fallback is unavailable")
            group.members, group.owners = set(), set()
            return group
        return self._migrate_group(doc, group)

    def _migrate_group(self, doc: TUserDbDocument, group: ScimApiGroup) -> ScimApiGroup:
        """
        Hydrate members/owners (and repair display_name) for a not-yet-migrated group from
        neo4j, and persist the result into mongodb without touching version/last_modified.
        """
        if self.graphdb is None:  # please mypy, caller already checked
            raise RuntimeError(f"_migrate_group called for group {group.scim_id} without a configured graphdb")
        graph = self.graphdb.get_group(str(group.scim_id))
        if graph is None:
            # A mongodb doc with no matching neo4j node (created after the cutover, or lost).
            # Migrate it as empty rather than raising.
            group.members, group.owners = set(), set()
            display_name = group.display_name
        else:
            group.members, group.owners = self._members_owners_from_graph(graph)
            # neo4j is authoritative for a not-yet-migrated group's display_name - the mongodb
            # value can be stale (e.g. never updated by a rename before this migration fixed
            # that), so repair it here.
            display_name = graph.display_name
            group.display_name = display_name
        update = {
            "members": _serialize_members(group.members),
            "owners": _serialize_members(group.owners),
            "display_name": display_name,
        }
        try:
            # $set only, and never version or last_modified - bumping either would break SCIM
            # clients doing incremental sync or invalidate every held ETag. Guarded on the
            # version we read plus members not already existing, so a concurrent save() (which
            # guards its own replace_one on the same version) can never be clobbered by this
            # write, and this write can't clobber a concurrent migration write either.
            res = self._coll.update_one(
                {"_id": group.group_id, "version": doc["version"], "members": {"$exists": False}},
                {"$set": update},
            )
            if res.modified_count == 0:
                # Somebody else (a concurrent save() or a concurrent migration) won the race.
                # Either way, mongodb is now authoritative and may disagree with the neo4j
                # snapshot we just read - e.g. a concurrent save() could have removed a member
                # that still appears in `group` here. Returning `group` as-is would resurrect
                # that membership, which is exactly what this migration must not do (especially
                # on the reverse-lookup union path). Reload the document that won instead.
                logger.info(f"Group {group.scim_id} was migrated concurrently; reloading the winning document")
                winning_doc = self._coll.find_one({"_id": group.group_id})
                if winning_doc is not None and winning_doc.get("members") is not None:
                    return ScimApiGroup.from_dict(winning_doc)
                # Pathological: the race didn't resolve the way it should have (e.g. the
                # document was deleted concurrently). Fall back to the neo4j-derived value
                # rather than crashing a read; a later read will retry.
                logger.warning(f"Group {group.scim_id}: concurrent migration race did not resolve as expected")
        except PyMongoError:
            # This is a read path - a mongodb write failure here must not turn a GET into a
            # 500. The members/owners we read from neo4j are still correct in memory even
            # though persisting them failed; the next read will simply re-migrate. Narrowly
            # scoped to PyMongoError (not Exception) so a real bug elsewhere isn't silently
            # swallowed and misreported as a transient write failure.
            logger.exception(f"Failed persisting migrated members/owners for group {group.scim_id}")
        return group

    @staticmethod
    def _merge_member_ts(
        new: set[ScimApiGroupMember], previous: list[Mapping[str, Any]] | None, now: datetime
    ) -> list[dict[str, Any]]:
        """
        Reimplements neo4j's `ON CREATE SET r.created_ts = timestamp()` /
        `ON MATCH SET r.modified_ts = timestamp()` semantics (see
        src/eduid/graphdb/groupdb/db.py) now that mongodb is the only store: a naive
        rebuild-from-the-set would reset created_ts to None on every save, since
        update_group's newly-constructed ScimApiGroupMember objects for changed members carry
        no timestamps at all.

        A member/owner unchanged since the previous save keeps its created_ts and
        modified_ts. A member whose display_name changed keeps created_ts but gets a fresh
        modified_ts. A genuinely new member gets created_ts=now and modified_ts=None.
        """
        old = {(d["member_type"], d["identifier"]): d for d in (previous or [])}
        out: list[dict[str, Any]] = []
        for m in sorted(new, key=_member_sort_key):
            prev = old.get((m.member_type.value, m.identifier))
            created_ts: datetime | None
            modified_ts: datetime | None
            if prev is None:
                created_ts, modified_ts = now, None
            elif prev.get("display_name") != m.display_name:
                created_ts, modified_ts = prev.get("created_ts"), now
            else:
                created_ts, modified_ts = prev.get("created_ts"), prev.get("modified_ts")
            out.append(
                {
                    "identifier": m.identifier,
                    "display_name": m.display_name,
                    "member_type": m.member_type.value,
                    "created_ts": created_ts,
                    "modified_ts": modified_ts,
                }
            )
        return out

    def save(self, group: ScimApiGroup) -> bool:
        if group.members is None or group.owners is None:
            raise RuntimeError(f"Refusing to save un-hydrated group {group.scim_id}")
        if group.members_truncated:
            raise RuntimeError(f"Refusing to save role-truncated group {group.scim_id}")

        # Read the previously stored members/owners (if any), so their created_ts/modified_ts
        # can be merged forward below instead of reset - see _merge_member_ts.
        previous = self._coll.find_one({"_id": group.group_id}, {"members": 1, "owners": 1})
        now = utc_now()

        previous_members = previous.get("members") if previous else None
        previous_owners = previous.get("owners") if previous else None

        # to_dict() would serialize group.members/owners via _serialize_members() only for the
        # result to be immediately overwritten by _merge_member_ts() below - skip that wasted
        # pass over a potentially large set by calling it on a members=None/owners=None copy
        # (to_dict() already special-cases None as "nothing to serialize").
        group_dict = replace(group, members=None, owners=None).to_dict()
        group_dict["members"] = self._merge_member_ts(group.members, previous_members, now)
        group_dict["owners"] = self._merge_member_ts(group.owners, previous_owners, now)

        test_doc = {
            "_id": group.group_id,
            "version": group.version,
        }
        # update the version number and last_modified timestamp
        group_dict["version"] = ObjectId()
        group_dict["last_modified"] = now
        result = self._coll.replace_one(test_doc, group_dict, upsert=False)
        if result.modified_count == 0:
            db_group = self._coll.find_one({"_id": group.group_id})
            if db_group:
                logger.debug(f"{self} FAILED Updating group {group} in {self._coll_name}")
                raise DocumentOutOfSync("Group out of sync, please retry")
            self._coll.insert_one(group_dict)
        # Nothing writes to neo4j from save() any more - mongodb is the sole write target.

        # put the new version number, last_modified and the merged members/owners in the group
        # object after a successful update, so the caller's object reflects what was actually
        # persisted (same as before, just sourced from the timestamp-merge above instead of
        # from a neo4j round trip).
        group.version = group_dict["version"]
        group.last_modified = group_dict["last_modified"]
        group.members = _members_from_docs(group_dict["members"])
        group.owners = _members_from_docs(group_dict["owners"])
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
        return [self._load_group(doc) for doc in docs]

    def get_group_by_scim_id(self, scim_id: str) -> ScimApiGroup | None:
        doc = self._get_document_by_attr("scim_id", scim_id)
        if doc:
            return self._load_group(doc)
        return None

    def get_group_by_display_name(self, display_name: str) -> ScimApiGroup | None:
        doc = self._get_document_by_attr("display_name", display_name)
        if doc:
            return self._load_group(doc)
        return None

    def get_groups_by_property(
        self, key: str, value: str | int, skip: int = 0, limit: int = 100
    ) -> tuple[list[ScimApiGroup], int]:
        docs, count = self._get_documents_and_count_by_filter({key: value}, skip=skip, limit=limit)
        if not docs:
            return [], 0
        return [self._load_group(doc) for doc in docs], count

    def get_groups_for_user_identifer(self, member_identifier: UUID) -> list[ScimApiGroup]:
        return self._get_groups_for_role(str(member_identifier), GroupRole.MEMBER)

    def get_groups_owned_by_user_identifier(self, owner_identifier: UUID) -> list[ScimApiGroup]:
        return self._get_groups_for_role(str(owner_identifier), GroupRole.OWNER)

    def _get_groups_for_role(self, identifier: str, role: GroupRole) -> list[ScimApiGroup]:
        """
        Reverse lookup - which groups is this identifier a member/owner of - consulting both
        mongodb (authoritative for every migrated group) and neo4j (fallback for groups not
        yet migrated), unioned by scim_id.
        """
        key = "members.identifier" if role is GroupRole.MEMBER else "owners.identifier"
        res: dict[str, ScimApiGroup] = {}

        # 1. mongodb leg - authoritative for every migrated group. A doc can only match this
        #    filter if its members/owners array already exists, i.e. it's already migrated, so
        #    _load_group() on it will never trigger a neo4j read - it's used here purely for
        #    consistency with every other read path.
        for doc in self._get_documents_by_filter({key: identifier}):
            group = self._load_group(doc)
            res[str(group.scim_id)] = self._project_for_role(group, identifier, role)

        if self.graphdb is None:
            return list(res.values())

        # 2. neo4j leg - only for groups NOT already found via mongodb above.
        graph_groups = (
            self.graphdb.get_groups_for_user_identifer(identifier)
            if role is GroupRole.MEMBER
            else self.graphdb.get_groups_owned_by_user_identifier(identifier)
        )
        for gg in graph_groups:
            if gg.identifier in res:
                continue  # already have the mongodb truth for this group
            neo4j_doc = self._get_document_by_attr("scim_id", gg.identifier)
            if neo4j_doc is None:
                # A group deleted from mongodb whose neo4j node survived (e.g. a remove_group
                # neo4j-delete failure, or a placeholder :Group node neo4j itself MERGEd for a
                # member-group reference that was never actually created as its own group). Do
                # NOT resurrect it - this is a deliberate, documented behavior change from before
                # (which used to raise RuntimeError here).
                logger.warning(f"Group {gg.identifier} found in neo4j but not in mongodb - ignoring")
                continue
            group = ScimApiGroup.from_dict(neo4j_doc)
            if group.members is not None and group.owners is not None:
                # Already migrated (this is a narrow race-window defensive branch - see below):
                # the neo4j edge we're looking at may be stale, e.g. a member removed after
                # migration, since nothing deletes neo4j edges any more once a group is
                # migrated. Re-evaluate against the mongodb doc we just read rather than
                # trusting the (possibly stale) neo4j edge.
                if not self._matches_role(group, identifier, role):
                    continue
            else:
                group = self._migrate_group(neo4j_doc, group)
                if not self._matches_role(group, identifier, role):
                    continue
            res[str(group.scim_id)] = self._project_for_role(group, identifier, role)

        return list(res.values())

    @staticmethod
    def _matches_role(group: ScimApiGroup, identifier: str, role: GroupRole) -> bool:
        members = group.members if role is GroupRole.MEMBER else group.owners
        return any(m.identifier == identifier for m in (members or set()))

    @staticmethod
    def _project_for_role(group: ScimApiGroup, identifier: str, role: GroupRole) -> ScimApiGroup:
        if role is GroupRole.MEMBER:
            # neo4j's own cypher only ever returns the querying entity as a member for a
            # MEMBER-role query (full member list only for an OWNER-role query) - this
            # asymmetry is an authorization boundary (see the comment at
            # webapp/group_management/helpers.py around merge_group_lists/is_owner/is_member)
            # and must be preserved regardless of which leg (mongodb or neo4j) answered.
            group.members = {m for m in (group.members or set()) if m.identifier == identifier}
            group.members_truncated = True
        return group

    def get_groups_by_last_modified(
        self, operator: str, value: datetime, limit: int | None = None, skip: int | None = None
    ) -> tuple[list[ScimApiGroup], int]:
        mongo_operator = self._get_mongo_operator(operator)
        spec = {"last_modified": {mongo_operator: value}}
        docs, total_count = self._get_documents_and_count_by_filter(spec=spec, limit=limit, skip=skip)
        groups = [self._load_group(doc) for doc in docs]
        return groups, total_count

    def group_exists(self, scim_id: str) -> bool:
        return bool(self.db_count(spec={"scim_id": scim_id}, limit=1))

    def remove_group(self, group: ScimApiGroup) -> bool:
        if not self.remove_document(group.group_id):
            return False
        if self.graphdb is not None:
            try:
                self.graphdb.remove_group(str(group.scim_id))
            except Exception:
                logger.exception(f"Failed removing group {group.scim_id} from neo4j - orphan node left behind")
        return True
