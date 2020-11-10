# -*- coding: utf-8 -*-
from __future__ import annotations

import copy
import logging
import pprint
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Type, Union
from uuid import UUID

from bson import ObjectId

from eduid_graphdb.groupdb import Group as GraphGroup
from eduid_graphdb.groupdb import GroupDB
from eduid_graphdb.groupdb import User as GraphUser

from eduid_scimapi.db.basedb import ScimApiBaseDB
from eduid_scimapi.schemas.group import Group as SCIMGroup

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


@dataclass
class GroupExtensions(object):
    data: Dict[str, Any] = field(default_factory=dict)  # arbitrary third party data

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_mapping(cls: Type[GroupExtensions], data: Mapping) -> GroupExtensions:
        return cls(data=data.get('data', {}),)


@dataclass
class ScimApiGroup:
    display_name: str
    group_id: ObjectId = field(default_factory=lambda: ObjectId())
    scim_id: UUID = field(default_factory=lambda: uuid.uuid4())
    version: ObjectId = field(default_factory=lambda: ObjectId())
    created: datetime = field(default_factory=lambda: datetime.utcnow())
    last_modified: datetime = field(default_factory=lambda: datetime.utcnow())
    extensions: GroupExtensions = field(default_factory=lambda: GroupExtensions())
    graph: GraphGroup = field(init=False)

    def __post_init__(self):
        self.graph = GraphGroup(identifier=str(self.scim_id), display_name=self.display_name)

    @property
    def members(self) -> Set[Union[GraphGroup, GraphUser]]:
        return self.graph.members

    @members.setter
    def members(self, members: Iterable[Union[GraphGroup, GraphUser]]):
        members = set(members)
        self.graph = replace(self.graph, members=members)

    def add_member(self, member: Union[GraphGroup, GraphUser]) -> None:
        self.graph.members.add(member)

    @property
    def owners(self) -> Set[Union[GraphGroup, GraphUser]]:
        return self.graph.owners

    @owners.setter
    def owners(self, owners: Iterable[Union[GraphGroup, GraphUser]]):
        owners = set(owners)
        self.graph = replace(self.graph, owners=owners)

    def add_owner(self, owner: Union[GraphGroup, GraphUser]) -> None:
        self.graph.owners.add(owner)

    def has_member(self, identifier: UUID) -> bool:
        return self.graph.has_member(str(identifier))

    def has_owner(self, identifier: UUID) -> bool:
        return self.graph.has_owner(str(identifier))

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res['scim_id'] = str(res['scim_id'])
        res['_id'] = res.pop('group_id')
        del res['graph']
        return res

    @classmethod
    def from_dict(cls: Type[ScimApiGroup], data: Mapping[str, Any]) -> ScimApiGroup:
        this = dict(copy.copy(data))  # to not modify callers data
        this['scim_id'] = uuid.UUID(this['scim_id'])
        this['group_id'] = this.pop('_id')
        this['extensions'] = GroupExtensions.from_mapping(this['extensions'])
        return cls(**this)


class ScimApiGroupDB(ScimApiBaseDB):
    def __init__(
        self,
        neo4j_uri: str,
        scope: str,
        mongo_uri: str,
        mongo_dbname: str,
        mongo_collection: str,
        neo4j_config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(mongo_uri, mongo_dbname, collection=mongo_collection)
        self.graphdb = GroupDB(db_uri=neo4j_uri, scope=scope, config=neo4j_config)
        logger.info(f'{self} initialised')

        # Create an index so that scim_id is unique per data owner
        indexes = {
            'unique-scimid': {'key': [('scim_id', 1)], 'unique': True},
        }
        self.setup_indexes(indexes)

    def save(self, group: ScimApiGroup) -> bool:
        group_dict = group.to_dict()

        test_doc = {
            '_id': group.group_id,
            'version': group.version,
        }
        # update the version number and last_modified timestamp
        group_dict['version'] = ObjectId()
        group_dict['last_modified'] = datetime.utcnow()
        result = self._coll.replace_one(test_doc, group_dict, upsert=False)
        if result.modified_count == 0:
            db_group = self._coll.find_one({'_id': group.group_id})
            if db_group:
                logger.debug(f'{self} FAILED Updating group {group} in {self._coll_name}')
                raise RuntimeError('Group out of sync, please retry')
            self._coll.insert_one(group_dict)
        # Save graphdb group
        # TODO: Should we try to roll back mongodb change if the graphdb save fails?
        group.graph = self.graphdb.save(group.graph)

        # put the new version number and last_modified in the group object after a successful update
        group.version = group_dict['version']
        group.last_modified = group_dict['last_modified']
        logger.debug(f'{self} Updated group {group} in {self._coll_name}')

        extra_debug = pprint.pformat(group_dict, width=120)
        logger.debug(f'Extra debug:\n{extra_debug}')

        return result.acknowledged

    def create_group(self, scim_group: SCIMGroup) -> ScimApiGroup:
        group = ScimApiGroup(
            extensions=GroupExtensions(data=scim_group.nutid_group_v1.data), display_name=scim_group.display_name
        )
        group.graph = GraphGroup(identifier=str(group.scim_id), display_name=scim_group.display_name)
        if not self.save(group):
            logger.error(f'Creating group {group} failed')
            raise RuntimeError('Group creation failed')
        return group

    def update_group(self, scim_group: SCIMGroup, db_group: ScimApiGroup) -> ScimApiGroup:
        changed = False
        updated_members = set()
        logger.info(f'Updating group {str(db_group.scim_id)}')
        for this in scim_group.members:
            if this.is_user:
                _member = db_group.graph.get_member_user(identifier=str(this.value))
                _new_member = None if _member else GraphUser(identifier=str(this.value), display_name=this.display)
            elif this.is_group:
                _member = db_group.graph.get_member_group(identifier=str(this.value))
                _new_member = None if _member else GraphGroup(identifier=str(this.value), display_name=this.display)
            else:
                raise ValueError(f"Don't recognise member {this}")

            # Add a new member
            if _new_member:
                updated_members.add(_new_member)
                logger.debug(f'Added new member: {_new_member}')
            # Update member attributes if they changed
            elif _member.display_name != this.display:
                logger.debug(f'Changed display name for existing member: {_member.display_name} -> {this.display}')
                _member = replace(_member, display_name=this.display)
                updated_members.add(_member)
            else:
                # no change, retain member as-is
                updated_members.add(_member)

        if db_group.graph.display_name != scim_group.display_name:
            changed = True
            logger.debug(f'Changed display name for group: {db_group.graph.display_name} -> {scim_group.display_name}')
            db_group.graph = replace(db_group.graph, display_name=scim_group.display_name)

        # Check if there where new, changed or removed members
        if db_group.graph.members != updated_members:
            changed = True
            logger.debug(f'Old members: {db_group.graph.members}')
            logger.debug(f'New members: {updated_members}')
            db_group.graph = replace(db_group.graph, members=updated_members)

        _sg_ext = GroupExtensions(data=scim_group.nutid_group_v1.data)
        if db_group.extensions != _sg_ext:
            changed = True
            logger.debug(f'Old extensions: {db_group.extensions}')
            logger.debug(f'New extensions: {_sg_ext}')
            db_group.extensions = _sg_ext

        if changed:
            logger.info(f'Group {str(db_group.scim_id)} changed. Saving.')
            if self.save(db_group):
                logger.info(f'Group {str(db_group.scim_id)} saved.')
            else:
                logger.warning(f'Update of group {db_group} probably failed')

        return db_group

    def get_groups(self) -> List[ScimApiGroup]:
        docs = self._get_documents_by_filter({}, raise_on_missing=False)
        res: List[ScimApiGroup] = []
        for doc in docs:
            group = ScimApiGroup.from_dict(doc)
            group.graph = self.graphdb.get_group(str(group.scim_id))
            res += [group]
        return res

    def get_group_by_scim_id(self, scim_id: str) -> Optional[ScimApiGroup]:
        doc = self._get_document_by_attr('scim_id', scim_id, raise_on_missing=False)
        if doc:
            group = ScimApiGroup.from_dict(doc)
            # TODO: Teach get_group raise_on_missing
            group.graph = self.graphdb.get_group(scim_id)
            if group.graph is None:
                raise RuntimeError(f'Group {scim_id} found in mongodb, but not in graphdb')
            return group
        return None

    def get_groups_by_property(
        self, key: str, value: Union[str, int], skip=0, limit=100
    ) -> Tuple[List[ScimApiGroup], int]:
        docs, count = self._get_documents_and_count_by_filter(
            {key: value}, skip=skip, limit=limit, raise_on_missing=False
        )
        if not docs:
            return [], 0
        res: List[ScimApiGroup] = []
        for this in docs:
            group = ScimApiGroup.from_dict(this)
            group.graph = self.graphdb.get_group(str(group.scim_id))
            res += [group]
        return res, count

    def get_groups_for_user_identifer(self, member_identifier: UUID) -> List[ScimApiGroup]:
        groups = self.graphdb.get_groups_for_user_identifer(str(member_identifier))
        res: List[ScimApiGroup] = []
        for graph in groups:
            group = self.get_group_by_scim_id(graph.identifier)
            if not group:
                raise RuntimeError(f'Group {graph} found in graph database, but not in mongodb')
            group.graph = graph
            res += [group]
        return res

    def get_groups_owned_by_user_identifier(self, owner_identifier: UUID) -> List[ScimApiGroup]:
        groups = self.graphdb.get_groups_owned_by_user_identifier(str(owner_identifier))
        res: List[ScimApiGroup] = []
        for graph in groups:
            group = self.get_group_by_scim_id(graph.identifier)
            if not group:
                raise RuntimeError(f'Group {graph} found in graph database, but not in mongodb')
            group.graph = graph
            res += [group]
        return res

    def get_groups_by_last_modified(
        self, operator: str, value: datetime, limit: Optional[int] = None, skip: Optional[int] = None
    ) -> Tuple[List[ScimApiGroup], int]:
        # map SCIM filter operators to mongodb filter
        mongo_operator = {'gt': '$gt', 'ge': '$gte'}.get(operator)
        if not mongo_operator:
            raise ValueError('Invalid filter operator')
        spec = {'last_modified': {mongo_operator: value}}
        docs, total_count = self._get_documents_and_count_by_filter(spec=spec, limit=limit, skip=skip)
        groups = [ScimApiGroup.from_dict(x) for x in docs]
        return groups, total_count

    def group_exists(self, scim_id: str) -> bool:
        return bool(self.db_count(spec={'scim_id': scim_id}, limit=1))

    def remove_group(self, group: ScimApiGroup) -> bool:
        if not self.remove_document(group.group_id):
            return False
        self.graphdb.remove_group(str(group.scim_id))
        return True
