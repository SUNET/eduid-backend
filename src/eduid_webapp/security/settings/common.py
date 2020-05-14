# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2019 SUNET
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

from __future__ import absolute_import

from dataclasses import dataclass, field
from typing import List

from eduid_common.config.base import FlaskConfig


@dataclass
class SecurityConfig(FlaskConfig):
    """
    Configuration for the security app
    """

    # timeout for phone verification token, in hours
    phone_verification_timeout: int = 24
    password_length: int = 12
    password_entropy: int = 25
    chpass_timeout: int = 600
    vccs_url: str = ''
    # uf2 settings
    u2f_app_id: str = 'https://eduid.se/u2f-app-id.json'
    u2f_max_allowed_tokens: int = 50  # Do not let a user register more than this amount of tokens
    u2f_max_description_length: int = 64  # Do not allow longer descriptions than this number
    u2f_facets: List[str] = field(default_factory=list)
    # webauthn
    webauthn_max_allowed_tokens: int = 10
    fido2_rp_id: str = 'eduid.se'
    # password reset settings
    email_code_timeout: int = 7200  # seconds
    phone_code_timeout: int = 600  # seconds
    # for logging out when terminating an account
    logout_endpoint: str = '/services/authn/logout'
    # URL to send the user to after terminating the account
    termination_redirect_url: str = 'https://eduid.se'
