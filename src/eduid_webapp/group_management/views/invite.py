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
#     3. Neither the name of the SUNET nor the names of its
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
from typing import Mapping
from uuid import UUID

from flask import Blueprint
from pymongo.errors import DuplicateKeyError

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid_common.api.exceptions import MailTaskFailed
from eduid_common.api.messages import CommonMsg, FluxData, error_response, success_response
from eduid_userdb import User
from eduid_userdb.exceptions import DocumentDoesNotExist, EduIDDBError
from eduid_userdb.group_management import GroupInviteState, GroupRole

from eduid_webapp.group_management.app import current_group_management_app as current_app
from eduid_webapp.group_management.helpers import (
    GroupManagementMsg,
    accept_group_invitation,
    get_incoming_invites,
    get_or_create_scim_user_by_eppn,
    get_outgoing_invites,
    get_scim_user_by_eppn,
    is_owner,
    send_invite_email,
)
from eduid_webapp.group_management.schemas import (
    GroupAllInviteResponseSchema,
    GroupIncomingInviteResponseSchema,
    GroupInviteRequestSchema,
    GroupOutgoingInviteResponseSchema,
)

__author__ = 'lundberg'

group_invite_views = Blueprint('group_invite', __name__, url_prefix='/invites/', template_folder='templates')


@group_invite_views.route('/all', methods=['GET'])
@MarshalWith(GroupAllInviteResponseSchema)
@require_user
def all_invites(user: User) -> FluxData:
    return success_response(payload={'incoming': get_incoming_invites(user), 'outgoing': get_outgoing_invites(user)})


@group_invite_views.route('/incoming', methods=['GET'])
@MarshalWith(GroupIncomingInviteResponseSchema)
@require_user
def incoming_invites(user: User) -> FluxData:
    return success_response(payload={'incoming': get_incoming_invites(user)})


@group_invite_views.route('/outgoing', methods=['GET'])
@MarshalWith(GroupOutgoingInviteResponseSchema)
@require_user
def outgoing_invites(user: User) -> FluxData:
    return success_response(payload={'outgoing': get_outgoing_invites(user)})


@group_invite_views.route('/create', methods=['POST'])
@UnmarshalWith(GroupInviteRequestSchema)
@MarshalWith(GroupOutgoingInviteResponseSchema)
@require_user
def create_invite(user: User, group_identifier: UUID, email_address: str, role: GroupRole) -> FluxData:
    scim_user = get_scim_user_by_eppn(user.eppn)
    if not scim_user:
        current_app.logger.error('User does not exist in scimapi_userdb')
        return error_response(message=GroupManagementMsg.user_does_not_exist)

    if not is_owner(scim_user, group_identifier):
        current_app.logger.error(f'User is not owner of group with scim_id: {group_identifier}')
        return error_response(message=GroupManagementMsg.user_not_owner)

    invite_state = GroupInviteState(
        group_scim_id=str(group_identifier), email_address=email_address, role=role, inviter_eppn=user.eppn
    )
    try:
        current_app.invite_state_db.save(invite_state)
    except DuplicateKeyError:
        current_app.logger.info(
            f'Invite for email address {invite_state.email_address} to group {invite_state.group_scim_id} '
            f'as role {invite_state.role.value} already exists.'
        )
    # Always send an e-mail even it the invite already existed
    try:
        send_invite_email(invite_state)
    except MailTaskFailed:
        return error_response(message=CommonMsg.temp_problem)
    current_app.stats.count(name='invite_created')
    return outgoing_invites()


@group_invite_views.route('/accept', methods=['POST'])
@UnmarshalWith(GroupInviteRequestSchema)
@MarshalWith(GroupIncomingInviteResponseSchema)
@require_user
def accept_invite(user: User, group_identifier: UUID, email_address: str, role: GroupRole) -> FluxData:
    # Check that the current user has verified the invited email address
    user_email_address = user.mail_addresses.find(email_address)
    if not user_email_address or not user_email_address.is_verified:
        current_app.logger.error(f'User has not verified email address: {email_address}')
        return error_response(message=GroupManagementMsg.mail_address_not_verified)

    invite_state = current_app.invite_state_db.get_state(
        group_scim_id=str(group_identifier), email_address=email_address, role=role, raise_on_missing=False
    )
    if not invite_state:
        current_app.logger.error(f'Invite for group {group_identifier} does not exist')
        return error_response(message=GroupManagementMsg.invite_not_found)

    # Invite exists and current user is the one invited
    scim_user = get_or_create_scim_user_by_eppn(user.eppn)

    group = current_app.scimapi_groupdb.get_group_by_scim_id(invite_state.group_scim_id)
    if not group:
        current_app.logger.error(f'Group with scim_id {invite_state.group_scim_id} not found')
        return error_response(message=GroupManagementMsg.group_not_found)

    # Try to add user to group
    try:
        accept_group_invitation(scim_user, group, invite_state)
    except EduIDDBError:
        return error_response(message=CommonMsg.temp_problem)

    current_app.invite_state_db.remove_state(invite_state)
    current_app.stats.count(name=f'invite_accepted_{invite_state.role.value}')
    return incoming_invites()


@group_invite_views.route('/decline', methods=['POST'])
@UnmarshalWith(GroupInviteRequestSchema)
@MarshalWith(GroupIncomingInviteResponseSchema)
@require_user
def decline_invite(user: User, group_identifier: UUID, email_address: str, role: GroupRole) -> FluxData:
    # Check that the current user has verified the invited email address
    user_email_address = user.mail_addresses.find(email_address)
    if not user_email_address or not user_email_address.is_verified:
        current_app.logger.error(f'User has not verified email address: {email_address}')
        return error_response(message=GroupManagementMsg.mail_address_not_verified)

    invite_state = current_app.invite_state_db.get_state(
        group_scim_id=str(group_identifier), email_address=email_address, role=role, raise_on_missing=False
    )
    if not invite_state:
        current_app.logger.error('Invite does not exist')
        return error_response(message=GroupManagementMsg.invite_not_found)

    # Remove group invite
    try:
        current_app.invite_state_db.remove_state(invite_state)
    except EduIDDBError:
        return error_response(message=CommonMsg.temp_problem)

    current_app.stats.count(name=f'invite_declined_{invite_state.role.value}')
    return incoming_invites()
