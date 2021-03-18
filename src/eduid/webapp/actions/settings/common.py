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
"""
Configuration (file) handling for the eduID actions app.
"""

from typing import Mapping

from pydantic import Field

from eduid.common.config.base import AmConfigMixin, EduIDBaseAppConfig, TouConfigMixin, WebauthnConfigMixin2


class ActionsConfig(EduIDBaseAppConfig, WebauthnConfigMixin2, AmConfigMixin, TouConfigMixin):
    """
    Configuration for the actions app
    """

    eduid_static_url: str

    app_name: str = 'actions'
    bundles_path: str = ''
    bundles_version: str = ''
    bundles_feature_cookie: str = ''
    bundles_feature_version: Mapping = Field(default_factory=dict)
    idp_url: str = ''
    mfa_testing: bool = False
    generate_u2f_challenges: bool = False  # UNUSED, remove after updating config everywhere
    eidas_url: str = ''
    mfa_authn_idp: str = ''
    # The plugins for pre-authentication actions that need to be loaded
    action_plugins: list = Field(default=['tou', 'mfa'])
