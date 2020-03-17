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
Configuration (file) handling for the eduID eidas app.
"""

from dataclasses import dataclass, field
from typing import Dict

from eduid_common.config.base import FlaskConfig


@dataclass
class EidasConfig(FlaskConfig):
    """
    Configuration for the eidas app
    """

    action_url: str = ''
    token_verify_redirect_url: str = '/profile/security'
    nin_verify_redirect_url: str = '/profile/nins'

    # Federation config
    authentication_context_map: Dict[str, str] = field(
        default_factory=lambda: {
            'loa1': 'http://id.elegnamnden.se/loa/1.0/loa1',
            'loa2': 'http://id.elegnamnden.se/loa/1.0/loa2',
            'loa3': 'http://id.elegnamnden.se/loa/1.0/loa3',
            'uncertified-loa3': 'http://id.swedenconnect.se/loa/1.0/uncertified-loa3',
            'loa4': 'http://id.elegnamnden.se/loa/1.0/loa4',
            'eidas-low': 'http://id.elegnamnden.se/loa/1.0/eidas-low',
            'eidas-sub': 'http://id.elegnamnden.se/loa/1.0/eidas-sub',
            'eidas-high': 'http://id.elegnamnden.se/loa/1.0/eidas-high',
            'eidas-nf-low': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-low',
            'eidas-nf-sub': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-sub',
            'eidas-nf-high': 'http://id.elegnamnden.se/loa/1.0/eidas-nf-high',
        }
    )

    # Authn algorithms
    authn_sign_alg: str = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    authn_digest_alg: str = 'http://www.w3.org/2001/04/xmlenc#sha256'

    # Staging nin map
    staging_nin_map: Dict[str, str] = field(
        default_factory=lambda: {
            #  'test nin': 'user nin'
        }
    )
