# -*- coding: utf-8 -*-
#
# Copyright (c) 2013-2016 NORDUnet A/S
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
from typing import Mapping, Optional

from pydantic import Field

from eduid.common.config.base import EduIDBaseAppConfig, ErrorsConfigMixin


class AuthnConfig(EduIDBaseAppConfig, ErrorsConfigMixin):
    """
    Configuration for the authn app
    """

    app_name: str = 'authn'
    server_name: str = 'authn'
    required_loa: Mapping[str, str] = Field(
        default={
            'personal': 'http://www.swamid.se/policy/assurance/al1',
            'helpdesk': 'http://www.swamid.se/policy/assurance/al2',
            'admin': 'http://www.swamid.se/policy/assurance/al3',
        }
    )
    available_loa: str = 'http://www.swamid.se/policy/assurance/al1'
    signup_authn_success_redirect_url: str = 'https://dashboard.eduid.se'
    signup_authn_failure_redirect_url: str = 'https://dashboard.eduid.se'
    unsolicited_response_redirect_url: str = 'https://dashboard.eduid.se'
    authn_sign_alg: Optional[str] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    authn_digest_alg: Optional[str] = 'http://www.w3.org/2001/04/xmlenc#sha256'
    saml2_login_redirect_url: str
    saml2_logout_redirect_url: str
    saml2_settings_module: str
    saml2_strip_saml_user_suffix: str

    token_service_url: str
    safe_relay_domain: str = 'eduid.se'
