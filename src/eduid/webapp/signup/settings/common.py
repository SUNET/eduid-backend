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
from datetime import timedelta
from pathlib import Path
from typing import List, Optional

import pkg_resources
from pydantic import AnyUrl, Field

from eduid.common.clients.gnap_client.base import GNAPClientAuthData
from eduid.common.config.base import (
    AmConfigMixin,
    EduIDBaseAppConfig,
    MagicCookieMixin,
    MailConfigMixin,
    TouConfigMixin,
)


class SignupConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin, MailConfigMixin, TouConfigMixin):
    """
    Configuration for the signup app
    """

    app_name = "signup"

    vccs_url: str
    signup_url: str
    dashboard_url: str
    default_language: str = "en"

    password_length: int = 10
    throttle_resend: timedelta = Field(default=timedelta(minutes=5))
    email_verification_code_length: int = 6
    email_verification_max_bad_attempts: int = 3
    email_verification_timeout: timedelta = Field(default=timedelta(minutes=10))
    email_proofing_version = Field(default="2013v1")
    default_finish_url: str = "https://www.eduid.se/"
    eduid_site_url: str = "https://www.eduid.se"  # TODO: Backwards compatibility, remove when no longer used
    eduid_site_name: str = "eduID"
    recaptcha_public_key: str = ""
    recaptcha_private_key: str = ""
    captcha_code_length: int = 6
    captcha_width: int = 160
    captcha_height: int = 60
    captcha_fonts: List[Path] = Field(
        default=[
            pkg_resources.resource_filename("eduid", "static/fonts/ProximaNova-Regular.ttf"),
            pkg_resources.resource_filename("eduid", "static/fonts/ProximaNova-Light.ttf"),
            pkg_resources.resource_filename("eduid", "static/fonts/ProximaNova-Bold.ttf"),
        ]
    )
    captcha_font_size: List[int] = [42, 50, 56]
    captcha_max_bad_attempts: int = 100
    captcha_backdoor_code: str = "123456"
    scim_api_url: Optional[AnyUrl] = None
    gnap_auth_data: Optional[GNAPClientAuthData] = None
    eduid_scope: str = "eduid.se"
    private_userdb_auto_expire: Optional[timedelta] = Field(default=timedelta(days=7))
