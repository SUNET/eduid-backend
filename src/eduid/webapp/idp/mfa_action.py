#
# Copyright (c) 2017 NORDUnet A/S
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
import logging
from typing import Optional

from eduid.userdb.credentials import Credential, FidoCredential
from eduid.userdb.credentials.external import BankIDCredential, SwedenConnectCredential
from eduid.userdb.idp.user import IdPUser
from eduid.webapp.common.session.namespaces import OnetimeCredential, OnetimeCredType
from eduid.webapp.idp.login_context import LoginContext

__author__ = "ft"

logger = logging.getLogger(__name__)


def need_security_key(user: IdPUser, ticket: LoginContext) -> bool:
    """Check if the user needs to use a Security Key for this very request, regardless of authnContextClassRef"""
    tokens = user.credentials.filter(FidoCredential)
    if not tokens:
        logger.debug("User has no FIDO credentials, no extra requirement for MFA this session imposed")
        return False

    for cred_key in ticket.pending_request.credentials_used:
        credential: Optional[Credential]
        if cred_key in ticket.pending_request.onetime_credentials:
            credential = ticket.pending_request.onetime_credentials[cred_key]
        else:
            credential = user.credentials.find(cred_key)
        if isinstance(credential, OnetimeCredential):
            # OLD way
            if credential.type == OnetimeCredType.external_mfa:
                logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                return False
        elif isinstance(credential, SwedenConnectCredential):
            # NEW way
            if credential.level == "loa3":
                logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                return False
        elif isinstance(credential, BankIDCredential):
            # NEW way
            if credential.level == "uncertified-loa3":
                logger.debug(f"User has authenticated using external MFA for this request: {credential}")
                return False
        elif isinstance(credential, FidoCredential):
            logger.debug(f"User has authenticated with a FIDO credential for this request: {credential}")
            return False

    logger.debug("User has one or more FIDO credentials registered, but haven't provided any MFA for this request")
    return True
