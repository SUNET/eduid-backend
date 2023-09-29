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

from typing import Optional

from pydantic import AnyUrl, Field, HttpUrl

from eduid.common.config.base import EduidEnvironment, PasswordConfigMixin


class JsAppsConfig(PasswordConfigMixin):
    """
    Dashboard, Signup and Login front-end configuration.

    This is sent to the client, so care must be taken to avoid setting secrets here.
    """

    available_languages: dict[str, str] = Field(default={"en": "English", "sv": "Svenska"})
    csrf_token: Optional[str] = None
    dashboard_link: HttpUrl
    dashboard_url: Optional[str]  # deprecated
    debug: bool = False
    eduid_site_link: HttpUrl = "https://eduid.se"
    eduid_site_name: str = "eduID"
    eduid_site_url: Optional[str] = "https://eduid.se"  # deprecated
    environment: EduidEnvironment = EduidEnvironment.production
    faq_link: HttpUrl
    reset_password_link: HttpUrl  # used for directing a user to the reset password app
    sentry_dsn: Optional[str] = None
    signup_link: HttpUrl
    signup_url: Optional[str]  # deprecated
    static_faq_url: Optional[str]  # deprecated
    # backend endpoint urls
    authn_service_url: HttpUrl
    authn_url: Optional[str]  # deprecated
    eidas_service_url: HttpUrl
    eidas_url: Optional[str]  # deprecated
    emails_service_url: HttpUrl
    emails_url: Optional[str]  # deprecated
    error_info_url: Optional[
        HttpUrl
    ] = None  # Needs to be a full URL since the backend is on the idp, not on https://eduid.se
    group_mgmt_service_url: HttpUrl
    group_mgmt_url: Optional[str]  # deprecated
    ladok_service_url: HttpUrl
    ladok_url: Optional[str]  # deprecated
    letter_proofing_service_url: HttpUrl
    letter_proofing_url: Optional[str]  # deprecated
    login_base_url: Optional[AnyUrl]  # deprecated
    login_next_url: HttpUrl  # Needs to be a full URL since the backend is on the idp, not on https://eduid.se
    login_request_other_url: Optional[
        HttpUrl
    ] = None  # Needs to be a full URL since the backend is on the idp, not on https://eduid.se
    login_service_url: HttpUrl
    lookup_mobile_proofing_service_url: HttpUrl
    lookup_mobile_proofing_url: Optional[str]  # deprecated
    orcid_service_url: HttpUrl
    orcid_url: Optional[str]  # deprecated
    personal_data_service_url: HttpUrl
    personal_data_url: Optional[str]  # deprecated
    phone_service_url: HttpUrl
    phone_url: Optional[str]  # deprecated
    reset_password_service_url: HttpUrl
    reset_password_url: Optional[str]  # deprecated
    security_service_url: HttpUrl
    security_url: Optional[str]  # deprecated
    svipe_service_url: Optional[HttpUrl]  # if not set the frontend component will not show
    svipe_url: Optional[str]  # deprecated
    # Dashboard config
    default_country_code: int = 46
    proofing_methods: list = Field(default=["letter", "lookup_mobile", "oidc", "eidas"])
    token_verify_idp: HttpUrl
    # Signup config
    recaptcha_public_key: Optional[str] = None
    tous: Optional[dict[str, str]] = None
