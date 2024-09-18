import logging
from dataclasses import replace
from typing import Any

from eduid.userdb.db import BaseDB, SaveResult
from eduid.userdb.group_management.state import GroupInviteState, GroupRole

logger = logging.getLogger(__name__)


class GroupManagementInviteStateDB(BaseDB):
    def __init__(self, db_uri: str, db_name: str = "eduid_group_management", collection: str = "group_invite_data"):
        super().__init__(db_uri, db_name, collection=collection)
        # Create an index so that invites for group_scim_id, email_address and role is unique
        indexes = {
            "unique-group-email-role": {
                "key": [("group_scim_id", 1), ("email_address", 1), ("role", 1)],
                "unique": True,
            }
        }
        self.setup_indexes(indexes)

    def get_state(self, group_scim_id: str, email_address: str, role: GroupRole) -> GroupInviteState | None:
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

    def get_states_by_group_scim_id(self, group_scim_id: str) -> list[GroupInviteState]:
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

    def get_states_by_email_addresses(self, email_addresses: list[str]) -> list[GroupInviteState]:
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

    def save(self, state: GroupInviteState, is_in_database: bool) -> SaveResult:
        """
        :param state: GroupInviteState object
        :param check_sync: Ensure the document hasn't been updated in the database since it was loaded
        """
        spec: dict[str, Any] = {
            "group_scim_id": state.group_scim_id,
            "email_address": state.email_address,
            "role": state.role,
        }

        result = self._save(state.to_dict(), spec, is_in_database=is_in_database)
        state = replace(state, modified_ts=result.ts)  # update to current time

        return result

    def remove_state(self, state: GroupInviteState) -> None:
        """
        :param state: GroupInviteState object
        """
        self.remove_document(
            {"group_scim_id": state.group_scim_id, "email_address": state.email_address, "role": state.role.value}
        )
