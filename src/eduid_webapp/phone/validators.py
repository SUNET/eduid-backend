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

import re

from marshmallow import ValidationError

from eduid_common.api.utils import get_user

from eduid_webapp.phone.app import current_phone_app as current_app


def normalize_to_e_164(number):
    number = ''.join(number.split())  # Remove white space
    if number.startswith(u'00'):
        raise ValidationError("phone.e164_format")
    if number.startswith(u'0'):
        country_code = current_app.config.default_country_code
        number = '+{}{}'.format(country_code, number[1:])
    return number


def validate_phone(number):
    validate_format_phone(number)
    validate_swedish_mobile(number)
    validate_unique_phone(number)


def validate_format_phone(number):
    if not re.match(r"^\+[1-9]\d{6,20}$", number):
        raise ValidationError("phone.phone_format")


def validate_swedish_mobile(number):
    if number.startswith(u'+467'):
        if not re.match(r"^\+467[02369]\d{7}$", number):
            raise ValidationError("phone.swedish_mobile_format")


def validate_unique_phone(number):
    user = get_user()
    if user.phone_numbers.find(number):
        raise ValidationError("phone.phone_duplicated")
