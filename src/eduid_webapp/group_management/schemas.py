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

from marshmallow import ValidationError, fields, post_load, pre_load

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid_common.api.schemas.validators import validate_email

from eduid_webapp.group_management.app import current_app

__author__ = 'lundberg'


def validate_role(role: str, **kwargs):
    """
    :param role: Role in group
    :return: True|ValidationError
    """
    roles = current_app.scimapi_groupdb.graphdb.Role.__members__.keys()
    if role.upper() in roles:
        return True
    raise ValidationError(f'role needs to be one of the following: {roles}')


class GroupMember(EduidSchema):
    identifier = fields.UUID(required=True)
    display_name = fields.Str(required=True)


class Group(EduidSchema):
    identifier = fields.UUID(required=True)
    display_name = fields.Str(required=True)
    members = fields.Nested(nested=GroupMember, default=[], many=True)
    owners = fields.Nested(nested=GroupMember, default=[], many=True)


class GroupManagementResponseSchema(FluxStandardAction):
    class GroupManagementResponsePayload(EduidSchema, CSRFResponseMixin):
        member_of = fields.Nested(Group, default=[], many=True)
        owner_of = fields.Nested(Group, default=[], many=True)

    payload = fields.Nested(GroupManagementResponsePayload)


class GroupCreateRequestSchema(EduidSchema, CSRFRequestMixin):

    display_name = fields.Str(required=True)


class GroupDeleteRequestSchema(EduidSchema, CSRFRequestMixin):

    identifier = fields.UUID(required=True)


class GroupInviteRequestSchema(EduidSchema, CSRFRequestMixin):

    identifier = fields.UUID(required=True)
    email_address = fields.Email(required=True, validate=[validate_email])
    role = fields.Str(required=True, validate=[validate_role])

    @post_load
    def lower_role(self, in_data, **kwargs):
        in_data["role"] = in_data["role"].lower()
        return in_data


class GroupInviteResponseSchema(FluxStandardAction):
    class GroupInviteResponsePayload(EduidSchema, CSRFResponseMixin):
        identifier = fields.UUID(required=True)
        email_address = fields.Email(required=True)
        role = fields.Str(required=True, validate=[validate_role])
        success = fields.Boolean(required=True)

    payload = fields.Nested(GroupInviteResponsePayload)
