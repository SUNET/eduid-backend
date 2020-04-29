# -*- coding: utf-8 -*-
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Dict, Mapping, Optional, Type
from uuid import uuid4

from bson import ObjectId

from eduid_groupdb import Group, GroupDB, User
from eduid_userdb.db import BaseDB

from eduid_scimapi.group import Group as SCIMGroup

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


@dataclass
class GroupAttrs(object):
    _id: Optional[ObjectId] = None  # mongodb document reference, to ensure we update the right document when saving
    data: Dict[str, Any] = field(default_factory=dict)  # arbitrary third party data

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        return res

    @classmethod
    def from_mapping(cls: Type[GroupAttrs], data: Mapping) -> GroupAttrs:
        return cls(_id=data.get('_id'), data=data.get('data', {}),)


@dataclass
class DBGroup(Group):
    attributes: GroupAttrs = field(default_factory=lambda: GroupAttrs())


class AttributeDB(BaseDB):
    def load_attributes(self, group: DBGroup) -> DBGroup:
        test_doc = {
            '_group_identifier': group.identifier,
        }
        docs = self._get_documents_by_filter(spec=test_doc, raise_on_missing=False)
        if not docs:
            return group
        if len(docs) != 1:
            raise RuntimeError(f'More than one set of attributes returned for identifier {group.identifier}')
        attr_dict = docs[0]['attributes']
        attr_dict['_id'] = docs[0]['_id']
        attrs = GroupAttrs.from_mapping(attr_dict)
        return replace(group, attributes=attrs)

    def save_attributes(self, group: DBGroup) -> DBGroup:
        _attr_dict = group.attributes.to_dict()
        # Don't store the _id redundantly in the attributes section - it is the document id
        # and explicitly put in the attr_doc above.
        _attr_dict.pop('_id', None)

        attr_doc = {
            '_id': group.attributes._id,
            '_group_identifier': group.identifier,
            'attributes': _attr_dict,
        }

        if group.attributes._id is None:
            # attributes never saved before
            del attr_doc['_id']
            res = self._coll.insert_one(attr_doc)
            new_attrs = replace(group.attributes, _id=res.inserted_id)
            return replace(group, attributes=new_attrs)

        # _id is not None, which means it should exist in the database
        test_doc = {
            '_id': group.attributes._id,
            '_group_identifier': group.identifier,
        }
        res = self._coll.replace_one(test_doc, attr_doc, upsert=False)
        if res.matched_count != 1:
            logger.error(f'{self} FAILED Updating attributes {group.attributes} in {self._coll_name}: {res}')
            raise RuntimeError('Group attributes out of sync')
        if res.modified_count != 1:
            logger.debug('The attributes were not modified')

        return group


class ScimApiGroupDB(GroupDB):
    def __init__(
        self,
        db_uri: str,
        scope: str,
        mongo_uri: str,
        mongo_dbname: str,
        mongo_collection: str,
        config: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(db_uri=db_uri, scope=scope, config=config)
        attr_db = AttributeDB(mongo_uri, mongo_dbname, mongo_collection)
        self._attr_db = attr_db
        logger.info(f'{self} initialised')

    def create_group(self, scim_group: SCIMGroup) -> DBGroup:
        group = Group(identifier=str(uuid4()), display_name=scim_group.display_name)
        saved_group = self.save(group)
        logger.info(f'Created scim_group: {saved_group.identifier}')
        logger.debug(f'Data: {saved_group}')
        db_group = DBGroup.from_mapping(asdict(saved_group))
        if scim_group.nutid_group_v1:
            _sg_attributes = GroupAttrs(_id=None, data=scim_group.nutid_group_v1.data)
            db_group.attributes = _sg_attributes
            logger.info(f'Group {db_group.identifier} attributes changed. Saving.')
            db_group = self.save_attributes(db_group)
        return db_group

    def get_group_by_scim_id(self, identifier: str) -> Optional[DBGroup]:
        group = self.get_group(identifier=identifier)
        return group

    def update_group(self, scim_group: SCIMGroup, db_group: DBGroup) -> DBGroup:
        changed = False
        member_changed = False
        members = []
        logger.info(f'Updating members for group {db_group.identifier}')
        for member in scim_group.members:
            user, group, update_member = None, None, None
            if 'Users' in member.ref:
                user = True
                update_member = db_group.get_member_user(identifier=str(member.value))
            elif 'Groups' in member.ref:
                group = True
                update_member = db_group.get_member_group(identifier=str(member.value))

            # Add a new member
            if update_member is None:
                member_changed = True
                if user:
                    update_member = User(identifier=str(member.value), display_name=member.display)
                elif group:
                    update_member = db_group.get_member_group(identifier=str(member.value))
                logger.debug(f'Added new member: {update_member}')
            # Update member attributes if they changed
            elif update_member.display_name != member.display:
                member_changed = True
                logger.debug(
                    f'Changed display name for existing member: {update_member.display_name} -> {member.display}'
                )
                update_member.display_name = member.display

            members.append(update_member)

        if db_group.display_name != scim_group.display_name:
            changed = True
            logger.debug(f'Changed display name for group: {db_group.display_name} -> {scim_group.display_name}')
            db_group.display_name = scim_group.display_name

        # Check if there where new, changed or removed members
        if member_changed or set(db_group.members) != set(members):
            changed = True
            logger.debug(f'Old members: {db_group.members}')
            logger.debug(f'New members: {members}')
            db_group.members = members

        _sg_attributes = GroupAttrs(_id=db_group.attributes._id, data=scim_group.nutid_group_v1.data)
        if db_group.attributes != _sg_attributes:
            logger.debug(f'Old attributes: {db_group.attributes}')
            logger.debug(f'New attributes: {_sg_attributes}')
            db_group.attributes = _sg_attributes
            logger.info(f'Group {db_group.identifier} attributes changed. Saving.')
            db_group = self.save_attributes(db_group)

        if changed:
            logger.info(f'Group {db_group.identifier} changed. Saving.')
            db_group = self.save(db_group)

        return db_group

    def save_attributes(self, group: DBGroup) -> DBGroup:
        if not self._attr_db:
            raise RuntimeError('No attribute database initialised')
        return self._attr_db.save_attributes(group)

    def _load_group(self, data: Dict) -> DBGroup:
        if not self._attr_db:
            raise RuntimeError('No attribute database initialised')
        db_group = DBGroup.from_mapping(data)
        return self._attr_db.load_attributes(db_group)
