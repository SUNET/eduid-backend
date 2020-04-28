# -*- coding: utf-8 -*-
import logging
from typing import List, Optional
from uuid import uuid4

from eduid_groupdb import Group, GroupDB, User
from eduid_groupdb.group import GroupAttrs

from eduid_scimapi.group import Group as SCIMGroup

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class ScimApiGroupDB(GroupDB):
    def create_group(self, scim_group: SCIMGroup) -> Group:
        group = Group(identifier=str(uuid4()), display_name=scim_group.display_name)
        saved_group = self.save(group)
        logger.info(f'Created scim_group: {saved_group.identifier}')
        logger.debug(f'Data: {saved_group}')

        return saved_group

    def get_group_by_scim_id(self, identifier: str) -> Optional[Group]:
        group = self.get_group(identifier=identifier)
        return group

    def update_group(self, scim_group: SCIMGroup, db_group: Group) -> Group:
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

        _sg_attributes = GroupAttrs(_id=db_group.attributes._id, attributes=scim_group.nutid_v1.attributes)
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
