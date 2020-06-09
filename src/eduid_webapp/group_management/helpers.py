# -*- coding: utf-8 -*-
from enum import unique
from typing import Optional
from uuid import UUID

from eduid_common.api.messages import TranslatableMsg
from eduid_groupdb import Group as GraphGroup
from eduid_groupdb import User as GraphUser
from eduid_scimapi.userdb import ScimApiUser
from eduid_userdb.exceptions import EduIDDBError
from eduid_userdb.group_management import GroupInviteState

from eduid_webapp.group_management.app import current_group_management_app as current_app

__author__ = 'lundberg'


@unique
class GroupManagementMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    user_does_not_exist = 'group.user_does_not_exist'
    group_not_found = 'group.group_not_found'
    invite_not_found = 'group.invite_not_found'
    create_failed = 'group.create_failed'
    user_not_owner = 'group.user_not_owner'
    mail_address_not_verified = 'group.mail_address_not_verified'
    invite_already_exists = 'group.invite_already_exists'


def get_scim_user_by_eppn(eppn: str) -> Optional[ScimApiUser]:
    external_id = f'{eppn}@{current_app.config.scim_external_id_scope}'
    return current_app.scimapi_userdb.get_user_by_external_id(external_id=external_id)


def is_owner(scim_user: ScimApiUser, group_id: UUID) -> bool:
    graph_user = GraphUser(identifier=str(scim_user.scim_id))
    owner_groups = current_app.scimapi_groupdb.get_groups_for_owner(graph_user)
    if group_id in [owner_group.scim_id for owner_group in owner_groups]:
        return True
    return False


def is_member(scim_user: ScimApiUser, group_id: UUID) -> bool:
    graph_user = GraphUser(identifier=str(scim_user.scim_id))
    member_groups = current_app.scimapi_groupdb.get_groups_for_member(graph_user)
    if group_id in [member_group.scim_id for member_group in member_groups]:
        return True
    return False


def add_user_to_group(scim_user: ScimApiUser, invite: GroupInviteState) -> bool:
    graph_user = GraphUser(identifier=str(scim_user.scim_id), display_name=invite.email_address)
    group = current_app.scimapi_groupdb.get_group_by_scim_id(invite.group_id)

    if not group:
        return False

    if invite.role == 'owner':
        group.graph.owners.append(graph_user)
    if invite.role == 'member':
        group.graph.members.append(graph_user)
    else:
        raise NotImplementedError(f'Unknown role: {invite.role}')

    if not current_app.scimapi_groupdb.save(group):
        current_app.logger.error(f'Failed to save group with scim_id: {invite.group_id}')
        raise EduIDDBError('Failed to save group')

    return True
