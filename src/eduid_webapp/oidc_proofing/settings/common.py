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

from __future__ import absolute_import

from dataclasses import dataclass, field
from typing import Dict

from eduid_common.config.base import FlaskConfig


@dataclass
class OIDCProofingConfig(FlaskConfig):
    """
    Configuration for the oidc proofing app
    """

    # OIDC
    client_registration_info: Dict[str, str] = field(
        default_factory=lambda: {'client_id': 'can_not_be_empty_string', 'client_secret': ''}
    )
    provider_configuration_info: Dict[str, str] = field(
        default_factory=lambda: {
            'issuer': 'can_not_be_empty_string',
            'authorization_endpoint': '',
            'jwks_uri': '',
            'response_types_supported': '',
            'subject_types_supported': '',
            'id_token_signing_alg_values_supported': '',
        }
    )
    userinfo_endpoint_method: str = 'POST'
    # Freja config
    freja_jws_algorithm: str = 'HS256'
    freja_jws_key_id: str = ''
    freja_jwk_secret: str = ''  # secret in hex
    freja_iarp: str = ''  # Relying party identity
    freja_expire_time_hours: int = 336  # 2 weeks, needs minimum 5 minutes and maximum 60 days
    freja_response_protocol: str = '1.0'  # Version
    # SE-LEG config
    seleg_expire_time_hours: int = 336  # Needs to be the same as FREJA_EXPIRE_TIME_HOURS as state is shared
