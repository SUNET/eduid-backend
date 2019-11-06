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
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class FrontConfig:
    """
    Dashboard front-end configuration.

    This is sent to the client, so care must be taken to avoid setting sectrets here.
    """
    debug: bool = False
    csrf_token: str = ''
    available_languages: Dict[str, str] = field(default_factory=lambda: {
            'en': 'English',
            'sv': 'Svenska',
            })
    tous: Dict[str, str] = field(default_factory=lambda: {
            'en': '',
            'sv': ''
            })
    # URLs
    static_faq_url: str = ''
    reset_passwd_url: str = ''
    dashboard_url: str = ''
    personal_data_url: str = '/personal-data/user'
    emails_url: str = '/services/email/'
    mobile_url: str = '/services/phone/'
    oidc_proofing_url: str = '/services/oidc-proofing/proofing/'
    lookup_mobile_proofing_url: str = '/services/lookup-mobile-proofing/proofing/'
    letter_proofing_url: str = '/services/letter-proofing/'
    security_url: str = '/services/security/'
    token_service_url: str = '/services/authn/'
    oidc_proofing_freja_url: str = '/services/oidc-proofing/freja/proofing/'
    orcid_url: str = '/services/orcid/'
    eidas_url: str = 'http://eidas.eduid.docker:8080/'
    token_verify_idp: str = 'http://dev.test.swedenconnect.se/idp'
    # changing password
    password_length: int = 12
    password_entropy: int = 25
    chpass_timeout: int = 600
    proofing_methods: list = field(default_factory=lambda: ['letter',
                                                            'lookup_mobile',
                                                            'oidc',
                                                            'eidas'])
    default_country_code: int = 46
    signup_authn_url: str = '/services/authn/signup-authn'
    # This key is for signup.eduid.docker:8080
    recaptcha_public_key: str = '6Lf5rCETAAAAAAW6UP4o59VSNEWG7RrzY_b5uH_M'
    # This key is for signup.eduid.local.emergya.info
    # recaptcha_public_key: str = '6Ld2IUwUAAAAAD5saiXoQKgmUC9JhQLqcHZoemTh'
    sentry_dsn: str = ''
