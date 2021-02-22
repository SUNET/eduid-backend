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
from typing import Optional

from eduid_common.config.base import AmConfigMixin, EduIDBaseAppConfig, MagicCookieMixin, MsgConfigMixin


class LetterProofingConfig(EduIDBaseAppConfig, MagicCookieMixin, AmConfigMixin, MsgConfigMixin):
    """
    Configuration for the letter proofing app
    """

    app_name: str = 'letter_proofing'

    letter_wait_time_hours: int = 336  # 2 weeks

    ekopost_api_uri: str = 'https://api.ekopost.se'
    ekopost_api_verify_ssl: bool = True
    ekopost_api_user: str = ''
    ekopost_api_pw: str = ''
    # Print in color (CMYK) or set to false for black and white.
    ekopost_api_color: bool = False
    # Send with 'priority' to deliver within one working day after printing, or send with 'economy' to deliver
    # within four working days after printing.
    ekopost_api_postage: str = 'priority'
    # Use 'simplex' to print on one page or 'duplex' to print on both front and back.
    ekopost_api_plex: str = 'simplex'
    ekopost_debug_pdf_path: Optional[str] = None

    # Remove expired states on GET /proofing if this is set to True
    backwards_compat_remove_expired_state: bool = False
