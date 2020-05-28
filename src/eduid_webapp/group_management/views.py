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
from typing import Dict, List, Mapping

from flask import Blueprint, jsonify

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid_groupdb import User as GraphUser
from eduid_scimapi.groupdb import ScimApiGroup
from eduid_userdb import User

from eduid_webapp.group_management.app import current_group_management_app as current_app
from eduid_webapp.group_management.schemas import GroupManagementResponseSchema

__author__ = 'lundberg'

group_management_views = Blueprint('group_management', __name__, url_prefix='', template_folder='templates')


def _list_of_group_data(group_list: List[ScimApiGroup]) -> List[Dict]:
    ret = []
    for group in group_list:
        members = [{'id': member.identifier, 'display_name': member.display_name} for member in group.graph.members]
        owners = [{'id': owner.identifier, 'display_name': owner.display_name} for owner in group.graph.owners]
        group_data = {
            'id': group.scim_id,
            'display_name': group.display_name,
            'members': members,
            'owners': owners,
        }
        current_app.logger.debug(f'Group data: {group_data}')
        ret.append(group_data)
    return ret


@group_management_views.route('/groups', methods=['GET'])
@MarshalWith(GroupManagementResponseSchema)
@require_user
def get_groups(user: User) -> Mapping:
    # TODO: get_user_by_eduid_eppn is not working anymore, do we want one?
    scim_user = current_app.scimapi_userdb.get_user_by_external_id(external_id=f'{user.eppn}@eduid.se')
    if not scim_user:
        current_app.logger.info(f'{user} does not exist in scimapi_userdb')
        return {}
    graph_user = GraphUser(identifier=str(scim_user.scim_id))
    member_groups = current_app.scimapi_groupdb.get_groups_for_member(member=graph_user)
    owner_groups = current_app.scimapi_groupdb.get_groups_for_owner(owner=graph_user)
    current_app.logger.debug(f'member_of: {member_groups}')
    current_app.logger.debug(f'owner_of: {owner_groups}')
    return {'member_of': _list_of_group_data(member_groups), 'owner_of': _list_of_group_data(owner_groups)}
