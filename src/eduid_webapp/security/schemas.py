# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
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
from eduid_common.api.schemas.base import FluxStandardAction, EduidSchema
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin


class CredentialSchema(EduidSchema):
    credential_type = fields.String(required=True)
    created_ts = fields.String(required=True)
    success_ts = fields.String(required=True)
    description = fields.String(required=False)


class CredentialList(EduidSchema, CSRFResponseMixin):
    credentials = fields.Nested(CredentialSchema, many=True)


class SecurityResponseSchema(FluxStandardAction):
    payload = fields.Nested(CredentialList)


class ChpassCredentialList(EduidSchema, CSRFResponseMixin):
    credentials = fields.Nested(CredentialSchema, many=True)
    next_url = fields.String(required=True)


class ChpassResponseSchema(FluxStandardAction):
    payload = fields.Nested(ChpassCredentialList, only=('credentials', 'next_url'))


class CsrfSchema(EduidSchema, CSRFRequestMixin):
    pass


class RedirectSchema(EduidSchema, CSRFResponseMixin):
    location = fields.String(required=True)


class RedirectResponseSchema(FluxStandardAction):

    payload = RedirectSchema()


class SuggestedPassword(EduidSchema, CSRFResponseMixin):

    suggested_password = fields.String(required=True)


class SuggestedPasswordResponseSchema(FluxStandardAction):

    payload = SuggestedPassword()


class ChangePasswordSchema(EduidSchema, CSRFRequestMixin):

    old_password = fields.String(required=True)
    new_password = fields.String(required=True)


class AccountTerminatedSchema(FluxStandardAction):
    pass


# U2F schemas
class U2FRegisteredKey(EduidSchema):

    version = fields.String(required=True)
    keyHandle = fields.String(required=True)
    appId = fields.String(required=True)
    transports = fields.String(required=True)


class U2FRegisterRequest(EduidSchema):

    version = fields.String(required=True)
    challenge = fields.String(required=True)


class U2FEnrollResponseSchema(FluxStandardAction, CSRFResponseMixin):

    appId = fields.String(required=True)
    registeredKeys = fields.Nested(U2FRegisteredKey, required=True, missing=list())
    registerRequests = fields.Nested(U2FRegisterRequest, required=True)


class U2FBindRequestSchema(EduidSchema, CSRFRequestMixin):

    version = fields.String(required=True)
    registration_data = fields.String(required=True)
    client_data = fields.String(required=True)


class U2FModifyRequestSchema(EduidSchema, CSRFRequestMixin):

    id = fields.String(required=True)
    description = fields.String(required=True)


class U2FSignResponseSchema(EduidSchema, CSRFResponseMixin):

    app_id = fields.String(required=True)
    challenge = fields.String(required=True)


class U2FVerifyRequestSchema(EduidSchema, CSRFRequestMixin):

    key_handle = fields.String(required=True)
    signature_data = fields.String(required=True)


class U2FVerifyResponseSchema(EduidSchema, CSRFResponseMixin):

    touch = fields.Integer(required=True)
    counter = fields.Integer(required=True)


class U2FRemoveRequestSchema(EduidSchema, CSRFRequestMixin):

    id = fields.String(required=True)

