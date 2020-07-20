# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
from typing import Dict, List
from uuid import UUID

from flask import Blueprint

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid_common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid_graphdb.groupdb import User as GraphUser
from eduid_scimapi.groupdb import ScimApiGroup
from eduid_userdb import User
from eduid_userdb.exceptions import EduIDDBError
from eduid_userdb.group_management import GroupRole

from eduid_webapp.group_management.app import current_group_management_app as current_app
from eduid_webapp.group_management.helpers import (
    GroupManagementMsg,
    get_all_group_data,
    get_incoming_invites,
    get_or_create_scim_user_by_eppn,
    get_outgoing_invites,
    get_scim_user_by_eppn,
    is_owner,
    remove_user_from_group,
)
from eduid_webapp.group_management.schemas import (
    GroupCreateRequestSchema,
    GroupDeleteRequestSchema,
    GroupManagementAllDataResponseSchema,
    GroupManagementResponseSchema,
    GroupRemoveUserRequestSchema,
)

__author__ = 'lundberg'

group_management_views = Blueprint('group_management', __name__, url_prefix='', template_folder='templates')


@group_management_views.route('/all-data', methods=['GET'])
@MarshalWith(GroupManagementAllDataResponseSchema)
@require_user
def get_all_data(user: User) -> FluxData:
    payload = {}
    scim_user = get_scim_user_by_eppn(user.eppn)
    if scim_user:
        # The user can only have group data if there is a scim user
        payload.update(get_all_group_data(scim_user))
    # Update payload with incoming and outgoing invites
    payload.update({'incoming': get_incoming_invites(user), 'outgoing': get_outgoing_invites(user)})
    return success_response(payload=payload)


@group_management_views.route('/groups', methods=['GET'])
@MarshalWith(GroupManagementResponseSchema)
@require_user
def get_groups(user: User) -> FluxData:
    scim_user = get_scim_user_by_eppn(user.eppn)
    if not scim_user:
        current_app.logger.info('User does not exist in scimapi_userdb')
        # As the user does not exist return empty group lists
        return success_response(payload={})
    payload = get_all_group_data(scim_user)
    return success_response(payload=payload)


@group_management_views.route('/create', methods=['POST'])
@UnmarshalWith(GroupCreateRequestSchema)
@MarshalWith(GroupManagementResponseSchema)
@require_user
def create_group(user: User, display_name: str) -> FluxData:
    scim_user = get_or_create_scim_user_by_eppn(user.eppn)
    graph_user = GraphUser(identifier=str(scim_user.scim_id), display_name=user.mail_addresses.primary.email)
    group = ScimApiGroup(display_name=display_name)
    group.owners = [graph_user]
    group.members = [graph_user]

    if not current_app.scimapi_groupdb.save(group):
        current_app.logger.error(f'Failed to create ScimApiGroup with scim_id: {group.scim_id}')
        return error_response(message=CommonMsg.temp_problem)

    current_app.logger.info(f'Created ScimApiGroup with scim_id: {group.scim_id}')
    current_app.stats.count(name='group_created')
    return get_groups()


@group_management_views.route('/delete', methods=['POST'])
@UnmarshalWith(GroupDeleteRequestSchema)
@MarshalWith(GroupManagementResponseSchema)
@require_user
def delete_group(user: User, group_identifier: UUID) -> FluxData:
    scim_user = get_scim_user_by_eppn(user.eppn)
    if not scim_user:
        current_app.logger.error('User does not exist in scimapi_userdb')
        return error_response(message=GroupManagementMsg.user_does_not_exist)

    if not is_owner(scim_user, group_identifier):
        current_app.logger.error(f'User is not owner of group with scim_id: {group_identifier}')
        return error_response(message=GroupManagementMsg.user_not_owner)

    group = current_app.scimapi_groupdb.get_group_by_scim_id(scim_id=str(group_identifier))
    if group and current_app.scimapi_groupdb.remove_group(group):
        # Remove outstanding invitations to the group
        for state in current_app.invite_state_db.get_states_by_group_scim_id(
            str(group_identifier), raise_on_missing=False
        ):
            current_app.invite_state_db.remove_state(state)
        current_app.logger.info(f'Deleted ScimApiGroup with scim_id: {group.scim_id}')
        current_app.stats.count(name='group_deleted')
    return get_groups()


@group_management_views.route('/remove-user', methods=['POST'])
@UnmarshalWith(GroupRemoveUserRequestSchema)
@MarshalWith(GroupManagementResponseSchema)
@require_user
def remove_user(user: User, group_identifier: UUID, user_identifier: UUID, role: GroupRole) -> FluxData:
    scim_user = get_scim_user_by_eppn(user.eppn)
    if not scim_user:
        current_app.logger.error('User does not exist in scimapi_userdb')
        return error_response(message=GroupManagementMsg.user_does_not_exist)

    _removing_self = user_identifier == scim_user.scim_id

    group = current_app.scimapi_groupdb.get_group_by_scim_id(scim_id=str(group_identifier))
    if not group:
        current_app.logger.error(f'Group with scim_id {group_identifier} not found')
        return error_response(message=GroupManagementMsg.group_not_found)

    # Check that it is either the user or a group owner that removes the user from the group
    if not _removing_self and not is_owner(scim_user, group_identifier):
        current_app.logger.error(f'User is not owner of group with scim_id: {group_identifier}')
        return error_response(message=GroupManagementMsg.user_not_owner)

    user_to_remove = current_app.scimapi_userdb.get_user_by_scim_id(scim_id=str(user_identifier))
    if not user_to_remove:
        current_app.logger.error('User to remove does not exist in scimapi_userdb')
        return error_response(message=GroupManagementMsg.user_to_be_removed_does_not_exist)

    # Check so we don't remove the last owner of a group
    if role == GroupRole.OWNER and len(group.owners) == 1:
        current_app.logger.error(f'Can not remove the last owner in group with scim_id: {group_identifier}')
        return error_response(message=GroupManagementMsg.can_not_remove_last_owner)

    try:
        remove_user_from_group(user_to_remove, group, role)
    except EduIDDBError:
        return error_response(message=CommonMsg.temp_problem)

    if _removing_self:
        # If the user initiates the removal count it as "left the group"
        current_app.stats.count(name=f'{role.value}_left_group')
    else:
        current_app.stats.count(name=f'{role.value}_removed_from_group')
    return get_groups()
