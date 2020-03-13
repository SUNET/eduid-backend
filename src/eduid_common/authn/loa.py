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
"""
Level of assurance related code.
"""

from .eduid_saml2 import get_authn_ctx

AVAILABLE_LOA_LEVEL = [
    'http://www.swamid.se/policy/assurance/al1',
    'http://www.swamid.se/policy/assurance/al2',
    'http://www.swamid.se/policy/assurance/al3',
]


MAX_LOA_ROL = {
    'user': AVAILABLE_LOA_LEVEL[0],
    'helpdesk': AVAILABLE_LOA_LEVEL[1],
    'admin': AVAILABLE_LOA_LEVEL[2],
}


def get_max_available_loa(groups):
    if not groups:
        return MAX_LOA_ROL['user']
    loas = [v for (k, v) in MAX_LOA_ROL.iteritems() if k in groups]
    if len(loas) > 0:
        return max(loas)
    else:
        return MAX_LOA_ROL['user']


def get_loa(available_loa, session_info):
    """
    Get the Assurance Level of the currently logged in users session.

    The difference between this and AuthnContext is that this function
    makes sure the returned value is known to this application.

    :param available_loa: List of permissible values. First one is default.
    :param session_info: The SAML2 session_info
    :return: The AL level

    :type available_loa: [string()]
    :type session_info: dict | None
    :rtype: string | None
    """
    if not available_loa:
        return AVAILABLE_LOA_LEVEL[0]

    default_loa = available_loa[0]

    if not session_info:
        return default_loa

    loa = get_authn_ctx(session_info)
    if loa in available_loa:
        return loa
    return default_loa
