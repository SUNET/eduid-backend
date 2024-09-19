from dataclasses import asdict, dataclass
from enum import unique
from typing import Any
from uuid import UUID

from flask_babel import gettext as _

from eduid.common.rpc.exceptions import MailTaskFailed
from eduid.graphdb.groupdb import Group as GraphGroup
from eduid.graphdb.groupdb import User as GraphUser
from eduid.userdb import User
from eduid.userdb.exceptions import EduIDDBError
from eduid.userdb.group_management import GroupInviteState
from eduid.userdb.scimapi import ScimApiGroup
from eduid.userdb.scimapi.userdb import ScimApiUser
from eduid.webapp.common.api.helpers import send_mail
from eduid.webapp.common.api.messages import TranslatableMsg
from eduid.webapp.group_management.app import current_group_management_app as current_app
from eduid.webapp.group_management.schemas import GroupRole

__author__ = "lundberg"


@unique
class GroupManagementMsg(TranslatableMsg):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """

    user_does_not_exist = "group.user_does_not_exist"
    user_to_be_removed_does_not_exist = "group.user_to_be_removed_does_not_exist"
    can_not_remove_last_owner = "group.can_not_remove_last_owner"
    group_not_found = "group.group_not_found"
    invite_not_found = "group.invite_not_found"
    create_failed = "group.create_failed"
    user_not_owner = "group.user_not_owner"
    mail_address_not_verified = "group.mail_address_not_verified"


@dataclass
class UserGroup:
    identifier: UUID
    display_name: str
    is_owner: bool
    is_member: bool
    owners: set[GraphUser | GraphGroup]
    members: set[GraphUser | GraphGroup]

    @classmethod
    def from_scimapigroup(cls, group: ScimApiGroup, is_owner: bool = False, is_member: bool = False):
        return cls(
            identifier=group.scim_id,
            display_name=group.display_name,
            is_owner=is_owner,
            is_member=is_member,
            owners=group.graph.owners,
            members=group.graph.members,
        )


def get_scim_user_by_eppn(eppn: str) -> ScimApiUser | None:
    external_id = f"{eppn}@{current_app.conf.scim_external_id_scope}"
    scim_user = current_app.scimapi_userdb.get_user_by_external_id(external_id=external_id)
    return scim_user


def get_or_create_scim_user_by_eppn(eppn: str) -> ScimApiUser:
    scim_user = get_scim_user_by_eppn(eppn)
    if not scim_user:
        scim_user = ScimApiUser(external_id=f"{eppn}@{current_app.conf.scim_external_id_scope}")
        current_app.scimapi_userdb.save(scim_user)
        current_app.logger.info(f"Created ScimApiUser with scim_id: {scim_user.scim_id}")
        current_app.stats.count(name="user_created")
    return scim_user


def merge_group_lists(owner_groups: list[ScimApiGroup], member_groups: list[ScimApiGroup]) -> list[UserGroup]:
    """
    :param owner_groups: Groups the user is owner to
    :param member_groups: Groups the user is member of
    :return: Combined group list for user
    """
    combined_groups = {}
    for group in owner_groups + member_groups:
        if group.scim_id in combined_groups:
            # only process each group once, and don't overwrite owner groups with
            # member groups (that don't show all members)
            continue
        combined_groups[group.scim_id] = UserGroup.from_scimapigroup(
            group,
            is_owner=group in owner_groups,
            is_member=group in member_groups,
        )
    return list(combined_groups.values())


def list_of_group_data(group_list: list[UserGroup]) -> list[dict]:
    ret = []
    for group in group_list:
        members = [{"identifier": member.identifier, "display_name": member.display_name} for member in group.members]
        owners = [{"identifier": owner.identifier, "display_name": owner.display_name} for owner in group.owners]
        group_data = asdict(group)
        group_data["owners"] = owners
        group_data["members"] = members
        current_app.logger.debug(f"Group data: {group_data}")
        ret.append(group_data)
    return ret


def get_all_group_data(scim_user: ScimApiUser) -> dict[str, Any]:
    member_groups = current_app.scimapi_groupdb.get_groups_for_user_identifer(scim_user.scim_id)
    owner_groups = current_app.scimapi_groupdb.get_groups_owned_by_user_identifier(scim_user.scim_id)
    combined_groups = merge_group_lists(owner_groups=owner_groups, member_groups=member_groups)
    current_app.logger.debug(f"member_of: {member_groups}")
    current_app.logger.debug(f"owner_of: {owner_groups}")
    current_app.logger.debug(f"combined: {combined_groups}")
    return {"user_identifier": scim_user.scim_id, "groups": list_of_group_data(combined_groups)}


def is_owner(scim_user: ScimApiUser, group_id: UUID) -> bool:
    owner_groups = current_app.scimapi_groupdb.get_groups_owned_by_user_identifier(scim_user.scim_id)
    return group_id in [owner_group.scim_id for owner_group in owner_groups]


def is_member(scim_user: ScimApiUser, group_id: UUID) -> bool:
    member_groups = current_app.scimapi_groupdb.get_groups_for_user_identifer(scim_user.scim_id)
    return group_id in [member_group.scim_id for member_group in member_groups]


def accept_group_invitation(scim_user: ScimApiUser, scim_group: ScimApiGroup, invite: GroupInviteState) -> None:
    graph_user = GraphUser(identifier=str(scim_user.scim_id), display_name=invite.email_address)
    modified = False
    if invite.role == GroupRole.OWNER:
        if not is_owner(scim_user, scim_group.scim_id):
            scim_group.add_owner(graph_user)
            modified = True
    elif invite.role == GroupRole.MEMBER:
        if not is_member(scim_user, scim_group.scim_id):
            scim_group.add_member(graph_user)
            modified = True
    else:
        raise NotImplementedError(f"Unknown role: {invite.role}")

    if modified:
        if not current_app.scimapi_groupdb.save(scim_group):
            current_app.logger.error(f"Failed to save group with scim_id: {invite.group_scim_id}")
            raise EduIDDBError("Failed to save group")
        current_app.logger.info(f"Added user as {invite.role.value} to group with scim_id: {invite.group_scim_id}")
    return None


def remove_user_from_group(scim_user: ScimApiUser, scim_group: ScimApiGroup, role: GroupRole) -> None:
    modified = False
    if role == GroupRole.OWNER:
        if is_owner(scim_user, scim_group.scim_id):
            scim_group.owners = {owner for owner in scim_group.owners if owner.identifier != str(scim_user.scim_id)}
            modified = True
    elif role == GroupRole.MEMBER:
        if is_member(scim_user, scim_group.scim_id):
            scim_group.members = {
                member for member in scim_group.members if member.identifier != str(scim_user.scim_id)
            }
            modified = True
    else:
        raise NotImplementedError(f"Unknown role: {role}")

    if modified:
        if not current_app.scimapi_groupdb.save(scim_group):
            raise EduIDDBError(f"Failed to save group with scim_id {scim_group.scim_id}")
        current_app.logger.info(
            f"Removed user as with scim_id {scim_user.scim_id} as {role.value} "
            f"from group with scim_id {scim_group.scim_id}"
        )
    return None


def get_outgoing_invites(user: User) -> list[dict[str, Any]]:
    """
    Return all outgoing invites to groups that the user is owner of.
    """
    invites: list[dict[str, Any]] = []
    scim_user = get_scim_user_by_eppn(user.eppn)
    if not scim_user:
        return invites

    groups = current_app.scimapi_groupdb.get_groups_owned_by_user_identifier(scim_user.scim_id)
    for group in groups:
        states = current_app.invite_state_db.get_states_by_group_scim_id(str(group.scim_id))
        if not states:
            continue
        owner_invites = []
        member_invites = []
        for state in states:
            if state.role == GroupRole.OWNER:
                owner_invites.append({"email_address": state.email_address})
            if state.role == GroupRole.MEMBER:
                member_invites.append({"email_address": state.email_address})
        group_invite = {
            "group_identifier": group.scim_id,
            "owner_invites": owner_invites,
            "member_invites": member_invites,
        }
        invites.append(group_invite)
    current_app.logger.debug(f"outgoing invites: {invites}")
    return invites


def get_incoming_invites(user: User) -> list[dict[str, Any]]:
    """
    Return all incoming invites to groups for the user
    """
    invites = []
    emails = [item.email for item in user.mail_addresses.verified]
    states = current_app.invite_state_db.get_states_by_email_addresses(emails)
    for state in states:
        group = current_app.scimapi_groupdb.get_group_by_scim_id(state.group_scim_id)
        if group is None:
            current_app.invite_state_db.remove_state(state)
            current_app.logger.info(f"Removed invite to non existent group: {state}")
            continue

        owners = [{"identifier": owner.identifier, "display_name": owner.display_name} for owner in group.owners]
        invites.append(
            {
                "group_identifier": group.scim_id,
                "display_name": group.display_name,
                "owners": owners,
                "email_address": state.email_address,
                "role": state.role,
            }
        )

    current_app.logger.debug(f"incoming invites: {invites}")
    return invites


def send_invite_email(invite_state: GroupInviteState):
    text_template = current_app.conf.group_invite_template_txt
    html_template = current_app.conf.group_invite_template_txt

    to_addresses = [invite_state.email_address]
    group = current_app.scimapi_groupdb.get_group_by_scim_id(invite_state.group_scim_id)
    if not group:
        raise ValueError(f"Group {invite_state.group_scim_id} not found")
    context = {"group_display_name": group.display_name, "group_invite_url": current_app.conf.group_invite_url}
    subject = _("Group invitation")
    try:
        send_mail(
            subject,
            to_addresses,
            text_template,
            html_template,
            current_app,
            context,
            reference=invite_state.group_scim_id,
        )
    except MailTaskFailed as e:
        current_app.logger.error(
            f"Sending group {invite_state.group_scim_id} invite email to {invite_state.email_address} failed: {e}"
        )
        raise e

    current_app.logger.info(f"Sent group {invite_state.group_scim_id} invite email to {invite_state.email_address}")


def send_delete_invite_email(invite_state: GroupInviteState):
    text_template = current_app.conf.group_delete_invite_template_txt
    html_template = current_app.conf.group_delete_invite_template_html

    to_addresses = [invite_state.email_address]
    group = current_app.scimapi_groupdb.get_group_by_scim_id(invite_state.group_scim_id)
    if not group:
        raise ValueError(f"Group {invite_state.group_scim_id} not found")
    context = {"group_display_name": group.display_name}
    subject = _("Group invitation cancelled")
    try:
        send_mail(
            subject,
            to_addresses,
            text_template,
            html_template,
            current_app,
            context,
            reference=invite_state.group_scim_id,
        )
    except MailTaskFailed as e:
        current_app.logger.error(
            f"Sending group {invite_state.group_scim_id} cancel invite email to "
            f"{invite_state.email_address} failed: {e}"
        )
        raise e

    current_app.logger.info(
        f"Sent group {invite_state.group_scim_id} cancel invite email to {invite_state.email_address}"
    )
