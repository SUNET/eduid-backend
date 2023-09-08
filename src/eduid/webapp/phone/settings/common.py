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
from pathlib import Path

import pkg_resources
from pydantic import Field

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, MagicCookieMixin, MsgConfigMixin


class PhoneConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin, MsgConfigMixin):
    """
    Configuration for the phone app
    """

    app_name: str = "phone"

    # timeout for phone verification token, in seconds
    phone_verification_timeout: int = 7200
    throttle_resend_seconds: int = 300
    # default country code
    default_country_code: str = "46"
    # captcha
    captcha_code_length: int = 6
    captcha_width: int = 160
    captcha_height: int = 60
    captcha_fonts: list[Path] = Field(
        default=[
            pkg_resources.resource_filename("eduid", "static/fonts/ProximaNova-Regular.ttf"),
            pkg_resources.resource_filename("eduid", "static/fonts/ProximaNova-Light.ttf"),
            pkg_resources.resource_filename("eduid", "static/fonts/ProximaNova-Bold.ttf"),
        ]
    )
    captcha_font_size: list[int] = [42, 50, 56]
    captcha_max_bad_attempts: int = 100
    captcha_backdoor_code: str = "123456"
