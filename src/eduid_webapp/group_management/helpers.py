# -*- coding: utf-8 -*-
from enum import unique
from typing import Any, Dict, List, Optional
from uuid import UUID

from eduid_common.api.messages import TranslatableMsg
from eduid_groupdb import User as GraphUser
from eduid_scimapi.groupdb import ScimApiGroup
from eduid_scimapi.userdb import ScimApiUser
from eduid_userdb import User
from eduid_userdb.exceptions import DocumentDoesNotExist, EduIDDBError
from eduid_userdb.group_management import GroupInviteState

from eduid_webapp.group_management.app import current_group_management_app as current_app
from eduid_webapp.group_management.schemas import GroupRole

__author__ = 'lundberg'


@unique
class GroupManagementMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    user_does_not_exist = 'group.user_does_not_exist'
    user_to_remove_does_not_exist = 'group.user_to_remove_does_not_exist'
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


def add_user_to_group(scim_user: ScimApiUser, scim_group: ScimApiGroup, invite: GroupInviteState) -> None:
    graph_user = GraphUser(identifier=str(scim_user.scim_id), display_name=invite.email_address)

    if invite.role == GroupRole.OWNER.value:
        if not is_owner(scim_user, scim_group.scim_id):
            scim_group.graph.owners.append(graph_user)
    elif invite.role == GroupRole.MEMBER.value:
        if not is_member(scim_user, scim_group.scim_id):
            scim_group.graph.members.append(graph_user)
    else:
        raise NotImplementedError(f'Unknown role: {invite.role}')

    if not current_app.scimapi_groupdb.save(scim_group):
        current_app.logger.error(f'Failed to save group with scim_id: {invite.group_scim_id}')
        raise EduIDDBError('Failed to save group')

    current_app.logger.info(f'Added user as {invite.role} to group with scim_id: {invite.group_scim_id}')
    return None


def remove_user_from_group(scim_user: ScimApiUser, scim_group: ScimApiGroup, role: str) -> None:
    if role == GroupRole.OWNER.value:
        if is_owner(scim_user, scim_group.scim_id):
            scim_group.graph.owners = [owner for owner in scim_group.graph.owners if owner.identifier != scim_user.scim_id]

    elif role == GroupRole.MEMBER.value:
        if is_member(scim_user, scim_group.scim_id):
            scim_group.graph.members = [member for member in scim_group.graph.members if member.identifier != scim_user.scim_id]
    else:
        raise NotImplementedError(f'Unknown role: {role}')

    if not current_app.scimapi_userdb.save(scim_group):
        raise EduIDDBError(f'Failed to save group with scim_id {scim_group.scim_id}')

    current_app.logger.info(f'Removed user as with scim_id {scim_user.scim_id} as {role} from group with scim_id {scim_group.scim_id}')
    return None


def get_outgoing_invites(groups: List[ScimApiGroup]) -> List[Dict[str, Any]]:
    """
    Return all outgoing invites to groups that the user is owner of.
    """
    invites = []
    for group in groups:
        try:
            states = current_app.invite_state_db.get_states_by_group_scim_id(str(group.scim_id))
        except DocumentDoesNotExist:
            continue
        group_invite = {'identifier': group.scim_id, 'owner_invites': [], 'member_invites': []}
        for state in states:
            if state.role == GroupRole.OWNER.value:
                group_invite['owner_invites'].append({'email_address': state.email_address})
            if state.role == GroupRole.MEMBER.value:
                group_invite['member_invites'].append({'email_address': state.email_address})
        invites.append(group_invite)
    current_app.logger.info(f'outgoing invites: {invites}')
    return invites


def get_incoming_invites(user: User) -> List[Dict[str, Any]]:
    """
    Return all incoming invites to groups for the user
    """
    invites = []
    emails = [item.email for item in user.mail_addresses.to_list() if item.is_verified]
    states = current_app.invite_state_db.get_states_by_email_addresses(emails, raise_on_missing=False)
    for state in states:
        group = current_app.scimapi_groupdb.get_group_by_scim_id(state.group_scim_id)
        if group is None:
            current_app.invite_state_db.remove_state(state)
            current_app.logger.info(f'Removed invite to non existant group: {state}')
            continue

        owners = [{'identifier': owner.identifier, 'display_name': owner.display_name} for owner in group.graph.owners]
        invites.append(
            {
                'identifier': group.scim_id,
                'display_name': group.display_name,
                'owners': owners,
                'email_address': state.email_address,
                'role': state.role,
            }
        )

    current_app.logger.info(f'incoming invites: {invites}')
    return invites
