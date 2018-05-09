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
from eduid_common.api.schemas.u2f import U2FEnrollResponseSchema, U2FBindRequestSchema, U2FSignResponseSchema
from eduid_common.api.schemas.u2f import U2FVerifyRequestSchema, U2FVerifyResponseSchema, U2FRegisteredKey
from eduid_common.api.schemas.nin import NinSchema
from eduid_common.api.schemas.validators import validate_nin


class CredentialSchema(EduidSchema):
    key = fields.String(required=True)
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
    payload = fields.Nested(ChpassCredentialList)


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
class ConvertRegisteredKeys(EduidSchema):
     
    class U2FRegisteredKey(EduidSchema):
        version = fields.String(required=True)
        keyhandle = fields.String(required=True, dump_to='keyHandle')
        app_id = fields.String(required=True, dump_to='appId')
        transports = fields.String()

    registered_keys = fields.Nested(U2FRegisteredKey, required=True, missing=list(), many=True)


class EnrollU2FTokenResponseSchema(FluxStandardAction):

    class EnrollU2FTokenResponsePayload(U2FEnrollResponseSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(EnrollU2FTokenResponsePayload)


class BindU2FRequestSchema(U2FBindRequestSchema, CSRFRequestMixin):

    description = fields.String(required=False)


class SignWithU2FTokenResponseSchema(FluxStandardAction):

    class Payload(U2FSignResponseSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(Payload)


class VerifyWithU2FTokenRequestSchema(U2FVerifyRequestSchema):
    pass


class VerifyWithU2FTokenResponseSchema(FluxStandardAction):

    class Payload(U2FVerifyResponseSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(Payload)


class ModifyU2FTokenRequestSchema(EduidSchema, CSRFRequestMixin):

    key_handle = fields.String(required=True, load_from='keyHandle', dump_to='keyHandle')
    description = fields.String(required=True)


class RemoveU2FTokenRequestSchema(EduidSchema, CSRFRequestMixin):

    key_handle = fields.String(required=True, load_from='keyHandle', dump_to='keyHandle')


# Remove NIN schemas
class RemoveNINRequestSchema(EduidSchema, CSRFRequestMixin):

    nin = fields.String(required=True, validate=validate_nin)


class RemoveNINResponseSchema(FluxStandardAction):

    class RemoveNINPayload(EduidSchema, CSRFResponseMixin):
        success = fields.Boolean(required=True)
        message = fields.String(required=False)
        nins = fields.Nested(NinSchema, many=True)

    payload = fields.Nested(RemoveNINPayload)
