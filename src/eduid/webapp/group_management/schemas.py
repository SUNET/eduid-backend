from marshmallow import fields
from marshmallow_enum import EnumField

from eduid.userdb.group_management import GroupRole
from eduid.webapp.common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid.webapp.common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid.webapp.common.api.schemas.email import LowercaseEmail
from eduid.webapp.common.api.schemas.validators import validate_email

__author__ = "lundberg"


class GroupUser(EduidSchema):
    identifier = fields.UUID(required=True)
    display_name = fields.Str(required=True)


class Group(EduidSchema):
    identifier = fields.UUID(required=True)
    display_name = fields.Str(required=True)
    is_member = fields.Bool(required=True)
    is_owner = fields.Bool(required=True)
    members = fields.Nested(nested=GroupUser, dump_default=[], load_default=[], many=True)
    owners = fields.Nested(nested=GroupUser, dump_default=[], load_default=[], many=True)


class OutgoingInvite(EduidSchema):
    class EmailAddress(EduidSchema):
        email_address = LowercaseEmail(required=True)

    group_identifier = fields.UUID(required=True)
    member_invites = fields.Nested(EmailAddress, many=True)
    owner_invites = fields.Nested(EmailAddress, many=True)


class IncomingInvite(EduidSchema):
    group_identifier = fields.UUID(required=True)
    display_name = fields.Str(required=True)
    email_address = LowercaseEmail(required=True)
    role = EnumField(GroupRole, required=True, by_value=True)
    owners = fields.Nested(GroupUser, many=True)


class GroupManagementResponseSchema(FluxStandardAction):
    class GroupManagementResponsePayload(EduidSchema, CSRFResponseMixin):
        user_identifier = fields.UUID(dump_default=None)
        groups = fields.Nested(Group, dump_default=[], many=True)

    payload = fields.Nested(GroupManagementResponsePayload)


class GroupCreateRequestSchema(EduidSchema, CSRFRequestMixin):
    display_name = fields.Str(required=True)


class GroupDeleteRequestSchema(EduidSchema, CSRFRequestMixin):
    group_identifier = fields.UUID(required=True)


class GroupRemoveUserRequestSchema(EduidSchema, CSRFRequestMixin):
    group_identifier = fields.UUID(required=True)
    user_identifier = fields.UUID(required=True)
    role = EnumField(GroupRole, required=True, by_value=True)


class GroupInviteRequestSchema(EduidSchema, CSRFRequestMixin):
    group_identifier = fields.UUID(required=True)
    email_address = LowercaseEmail(required=True, validate=validate_email)
    role = EnumField(GroupRole, required=True, by_value=True)


class GroupIncomingInviteResponseSchema(FluxStandardAction):
    class GroupInviteResponsePayload(EduidSchema, CSRFResponseMixin):
        incoming = fields.Nested(IncomingInvite, many=True)

    payload = fields.Nested(GroupInviteResponsePayload)


class GroupOutgoingInviteResponseSchema(FluxStandardAction):
    class GroupInviteResponsePayload(EduidSchema, CSRFResponseMixin):
        outgoing = fields.Nested(OutgoingInvite, many=True)

    payload = fields.Nested(GroupInviteResponsePayload)


class GroupAllInviteResponseSchema(FluxStandardAction):
    class GroupInviteResponsePayload(EduidSchema, CSRFResponseMixin):
        incoming = fields.Nested(IncomingInvite, many=True)
        outgoing = fields.Nested(OutgoingInvite, many=True)

    payload = fields.Nested(GroupInviteResponsePayload)


class GroupManagementAllDataResponseSchema(FluxStandardAction):
    class CombinedGroupDataInviteDataPayload(EduidSchema, CSRFResponseMixin):
        user_identifier = fields.UUID(dump_default=None)
        groups = fields.Nested(Group, dump_default=[], many=True)
        incoming = fields.Nested(IncomingInvite, many=True)
        outgoing = fields.Nested(OutgoingInvite, many=True)

    payload = fields.Nested(CombinedGroupDataInviteDataPayload)
