# -*- coding: utf-8 -*-
#
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

from typing import Dict, Optional

from pydantic import Field

from eduid.common.config.base import EduidEnvironment, PasswordConfigMixin


class JsAppsConfig(PasswordConfigMixin):
    """
    Dashboard, Signup and Login front-end configuration.

    This is sent to the client, so care must be taken to avoid setting secrets here.
    """

    debug: bool = False
    environment: EduidEnvironment = EduidEnvironment.production
    csrf_token: Optional[str] = None
    available_languages: Dict[str, str] = Field(default={'en': 'English', 'sv': 'Svenska'})
    eduid_site_name: str = 'eduID'
    eduid_site_url: str = 'https://eduid.se'
    dashboard_url: str
    signup_url: str
    reset_password_link: str  # used for directing a user to the reset password app
    static_faq_url: str
    sentry_dsn: Optional[str] = None
    # backend endpoint urls
    authn_url: str
    eidas_url: str
    emails_url: str
    group_mgmt_url: str
    ladok_url: str
    letter_proofing_url: str
    login_next_url: str
    lookup_mobile_proofing_url: str
    mobile_url: Optional[str] = None  # should be replaced by phone_url
    oidc_proofing_freja_url: str
    oidc_proofing_url: str
    orcid_url: str
    password_service_url: Optional[str] = None  # should be replaced by reset_password_url
    personal_data_url: str
    phone_url: str
    reset_passwd_url: Optional[str] = None  # should be replaced by reset_password_url
    reset_password_url: str
    security_url: str
    token_service_url: Optional[str] = None  # should be replaced by authn_url
    # Dashboard config
    proofing_methods: list = Field(default=['letter', 'lookup_mobile', 'oidc', 'eidas'])
    default_country_code: int = 46
    token_verify_idp: str
    # Signup config
    tous: Optional[Dict[str, str]] = None
    recaptcha_public_key: Optional[str] = None
