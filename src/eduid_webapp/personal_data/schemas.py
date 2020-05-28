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

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin
from eduid_common.api.schemas.nin import NinSchema
from eduid_common.api.schemas.orcid import OrcidSchema

from eduid_webapp.email.schemas import EmailSchema
from eduid_webapp.personal_data.validators import validate_language, validate_nonempty
from eduid_webapp.phone.schemas import PhoneSchema

__author__ = 'eperez'


class PersonalDataRequestSchema(EduidSchema, CSRFRequestMixin):

    given_name = fields.String(required=True, validate=validate_nonempty)
    surname = fields.String(required=True, validate=validate_nonempty)
    display_name = fields.String(required=True, validate=validate_nonempty)
    language = fields.String(required=True, default='en', validate=validate_language)


class PersonalDataSchema(EduidSchema):

    given_name = fields.String(required=True, attribute='givenName')
    surname = fields.String(required=True)
    display_name = fields.String(required=True, attribute='displayName')
    language = fields.String(required=True, attribute='preferredLanguage', validate=validate_language)


class PersonalDataResponseSchema(FluxStandardAction):
    class PersonalDataResponsePayload(PersonalDataSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(PersonalDataResponsePayload)


class NinsResponseSchema(FluxStandardAction):
    class NinResponsePayload(EmailSchema, CSRFResponseMixin):
        nins = fields.Nested(NinSchema, many=True)

    payload = fields.Nested(NinResponsePayload)


class AllDataSchema(EduidSchema):
    eppn = fields.String(required=True, attribute='eduPersonPrincipalName')
    given_name = fields.String(required=True, attribute='givenName')
    surname = fields.String(required=True)
    display_name = fields.String(required=True, attribute='displayName')
    language = fields.String(required=True, attribute='preferredLanguage', validate=validate_language)
    nins = fields.Nested(NinSchema, many=True)
    emails = fields.Nested(EmailSchema, many=True, attribute='mailAliases')
    phones = fields.Nested(PhoneSchema, many=True, attribute='phone')
    orcid = fields.Nested(OrcidSchema, attribute='orcid')


class AllDataResponseSchema(FluxStandardAction):
    class AllDataResponsePayload(AllDataSchema, CSRFResponseMixin):
        pass

    payload = fields.Nested(AllDataResponsePayload)
