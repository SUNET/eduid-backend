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

from marshmallow import fields, pre_load

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFRequestMixin, CSRFResponseMixin

from eduid_webapp.phone.validators import normalize_to_e_164, validate_format_phone, validate_phone

__author__ = 'eperez'


class VerificationCodeSchema(EduidSchema, CSRFRequestMixin):

    code = fields.String(required=True)
    number = fields.String(required=True, validate=validate_format_phone)


class PhoneSchema(EduidSchema, CSRFRequestMixin):

    number = fields.String(required=True, validate=validate_phone)
    verified = fields.Boolean(attribute='verified')
    primary = fields.Boolean(attribute='primary')

    @pre_load
    def normalize_phone_number(self, in_data, **kwargs):
        if in_data.get('number'):
            in_data['number'] = normalize_to_e_164(in_data['number'])
        return in_data


class PhoneListPayload(EduidSchema, CSRFRequestMixin, CSRFResponseMixin):

    phones = fields.Nested(PhoneSchema, many=True)


class PhoneResponseSchema(FluxStandardAction):

    payload = fields.Nested(PhoneListPayload)


class SimplePhoneSchema(EduidSchema, CSRFRequestMixin):

    number = fields.String(required=True)
