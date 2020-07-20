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

from marshmallow import fields
from marshmallow_enum import EnumField

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid_common.api.schemas.validators import validate_email
from eduid_userdb.group_management import GroupRole

__author__ = 'lundberg'


class LowerEmail(fields.Email):
    def _serialize(self, value, attr, obj, **kwargs):
        value = super()._serialize(value, attr, obj, **kwargs)
        return value.lower()

    def _deserialize(self, value, attr, data, **kwargs):
        value = super()._deserialize(value, attr, data, **kwargs)
        return value.lower()


class GroupUser(EduidSchema):
    identifier = fields.UUID(required=True)
    display_name = fields.Str(required=True)


class Group(EduidSchema):
    identifier = fields.UUID(required=True)
    display_name = fields.Str(required=True)
    members = fields.Nested(nested=GroupUser, default=[], many=True)
    owners = fields.Nested(nested=GroupUser, default=[], many=True)


class OutgoingInvite(EduidSchema):
    class EmailAddress(EduidSchema):
        email_address = LowerEmail(required=True)

    group_identifier = fields.UUID(required=True)
    member_invites = fields.Nested(EmailAddress, many=True)
    owner_invites = fields.Nested(EmailAddress, many=True)


class IncomingInvite(EduidSchema):
    group_identifier = fields.UUID(required=True)
    display_name = fields.Str(required=True)
    email_address = LowerEmail(required=True)
    role = EnumField(GroupRole, required=True, by_value=True)
    owners = fields.Nested(GroupUser, many=True)


class GroupManagementResponseSchema(FluxStandardAction):
    class GroupManagementResponsePayload(EduidSchema, CSRFResponseMixin):
        member_of = fields.Nested(Group, default=[], many=True)
        owner_of = fields.Nested(Group, default=[], many=True)

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
    email_address = fields.Email(required=True, validate=validate_email)
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
        member_of = fields.Nested(Group, default=[], many=True)
        owner_of = fields.Nested(Group, default=[], many=True)
        incoming = fields.Nested(IncomingInvite, many=True)
        outgoing = fields.Nested(OutgoingInvite, many=True)

    payload = fields.Nested(CombinedGroupDataInviteDataPayload)
