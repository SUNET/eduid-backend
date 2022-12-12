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
import logging
from dataclasses import replace
from typing import Any, Dict, List, Optional

from eduid.userdb.db import BaseDB, SaveResult
from eduid.userdb.group_management.state import GroupInviteState, GroupRole

logger = logging.getLogger(__name__)


class GroupManagementInviteStateDB(BaseDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_group_management", collection: str = "group_invite_data"):
        super(GroupManagementInviteStateDB, self).__init__(db_uri, db_name, collection=collection)
        # Create an index so that invites for group_scim_id, email_address and role is unique
        indexes = {
            "unique-group-email-role": {
                "key": [("group_scim_id", 1), ("email_address", 1), ("role", 1)],
                "unique": True,
            }
        }
        self.setup_indexes(indexes)

    def get_state(self, group_scim_id: str, email_address: str, role: GroupRole) -> Optional[GroupInviteState]:
        """
        :param group_scim_id: Groups unique identifier
        :param email_address: Invited email address
        :param role: Group role
        """
        spec = {"group_scim_id": group_scim_id, "email_address": email_address, "role": role.value}
        docs = list(self._get_documents_by_filter(spec))
        if len(docs) == 1:
            return GroupInviteState.from_dict(docs[0])
        return None

    def get_states_by_group_scim_id(self, group_scim_id: str) -> List[GroupInviteState]:
        """
        Locate a state in the db given the state's group identifier.

        :param group_scim_id: Groups unique identifier

        :return: List of GroupInviteState instances

        :raise self.DocumentDoesNotExist: No document match the search criteria
        """
        spec = {"group_scim_id": group_scim_id}
        states = list(self._get_documents_by_filter(spec))

        if len(states) == 0:
            return []

        return [GroupInviteState.from_dict(state) for state in states]

    def get_states_by_email_addresses(self, email_addresses: List[str]) -> List[GroupInviteState]:
        """
        Locate a state in the db given the state's group identifier.

        :param email_addresses: List of a users verified email addresses

        :return: List of GroupInviteState instances

        :raise self.DocumentDoesNotExist: No document match the search criteria
        """
        states: list[GroupInviteState] = []
        for email_address in email_addresses:
            spec = {"email_address": email_address}
            for this in self._get_documents_by_filter(spec):
                states.append(GroupInviteState.from_dict(this))

        return states

    def save(self, state: GroupInviteState, check_sync: bool = True) -> SaveResult:
        """
        :param state: GroupInviteState object
        :param check_sync: Ensure the document hasn't been updated in the database since it was loaded
        """
        spec: Dict[str, Any] = {
            "group_scim_id": state.group_scim_id,
            "email_address": state.email_address,
            "role": state.role,
        }

        result = self._save(state.to_dict(), spec, check_sync)
        state = replace(state, modified_ts=result.ts)  # update to current time

        return result

    def remove_state(self, state: GroupInviteState) -> None:
        """
        :param state: GroupInviteState object
        """
        self.remove_document(
            {"group_scim_id": state.group_scim_id, "email_address": state.email_address, "role": state.role.value}
        )
