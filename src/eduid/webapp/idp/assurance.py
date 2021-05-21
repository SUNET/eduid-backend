#!/usr/bin/python
#
# Copyright (c) 2013, 2014 NORDUnet A/S
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
# Author : Fredrik Thulin <fredrik@thulin.net>
#
import logging
from enum import Enum, unique
from typing import List, Optional, Sequence, Union

from eduid.userdb.credentials import (
    METHOD_SWAMID_AL2_MFA,
    METHOD_SWAMID_AL2_MFA_HI,
    Credential,
    FidoCredential,
    Password,
)
from eduid.userdb.idp import IdPUser
from eduid.webapp.common.session.logindata import SSOLoginData
from eduid.webapp.common.session.namespaces import OnetimeCredential, OnetimeCredType
from eduid.webapp.idp.app import current_idp_app
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.idp_saml import AuthnInfo
from eduid.webapp.idp.sso_session import SSOSession
from eduid.webapp.idp.util import logger

logger = logging.getLogger(__name__)

"""
Assurance Level functionality.
"""


@unique
class EduidAuthnContextClass(Enum):
    REFEDS_MFA = 'https://refeds.org/profile/mfa'
    REFEDS_SFA = 'https://refeds.org/profile/sfa'
    FIDO_U2F = 'https://www.swamid.se/specs/id-fido-u2f-ce-transports'
    EDUID_MFA = 'https://eduid.se/specs/mfa'
    PASSWORD_PT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'


class AssuranceException(Exception):
    pass


class MissingSingleFactor(AssuranceException):
    pass


class MissingPasswordFactor(AssuranceException):
    pass


class MissingMultiFactor(AssuranceException):
    pass


class WrongMultiFactor(AssuranceException):
    pass


class MissingAuthentication(AssuranceException):
    pass


class AuthnState(object):
    def __init__(self, user: IdPUser, sso_session: SSOSession, ticket: SSOLoginData):
        # authn_credentials is a list of dicts created by AuthnData.to_session_dict(), e.g.:
        # {'cred_id': self.credential.key,
        #  'authn_ts': self.timestamp,
        # }
        self.password_used = False
        self.is_swamid_al2 = False
        self.fido_used = False
        self.external_mfa_used = False
        self.swamid_al2_used = False
        self.swamid_al2_hi_used = False
        self._creds: List[Union[Credential, OnetimeCredential]] = []

        if not ticket.saml_req.force_authn:
            # Request does not have forceAuthn set, so gather credentials from the SSO session
            for this in sso_session.authn_credentials:
                cred = user.credentials.find(this.cred_id)
                if not cred:
                    logger.warning(f'Could not find credential {this.cred_id} on user {user}')
                    continue
                logger.debug(f'Inheriting used credential: {cred} ({this.timestamp.isoformat()})')
                self._creds += [cred]

            # External mfa check
            if sso_session.external_mfa is not None:
                logger.debug(f'External MFA (in SSO session) issuer: {sso_session.external_mfa.issuer}')
                self._creds += [
                    OnetimeCredential(
                        authn_context=sso_session.external_mfa.authn_context,
                        issuer=sso_session.external_mfa.issuer,
                        timestamp=sso_session.external_mfa.timestamp,
                        type=OnetimeCredType.external_mfa,
                    )
                ]
                self.external_mfa_used = True
                # TODO: Support more SwedenConnect authn contexts?
                if sso_session.external_mfa.authn_context == 'http://id.elegnamnden.se/loa/1.0/loa3':
                    self.swamid_al2_hi_used = True

        for key, ts in ticket.saml_data.credentials_used.items():
            if key in ticket.saml_data.onetime_credentials:
                onetime_cred = ticket.saml_data.onetime_credentials[key]
                self._creds += [onetime_cred]
            else:
                cred = user.credentials.find(key)
                if not cred:
                    logger.warning(f'Could not find credential {key} on user {user}')
                    continue
                logger.debug(f'Adding used credential: {cred} ({ts.isoformat()})')
                self._creds += [cred]

        for cred in self._creds:
            if isinstance(cred, Password):
                self.password_used = True
            elif isinstance(cred, FidoCredential):
                self.fido_used = True
                if cred.is_verified:
                    if cred.proofing_method == METHOD_SWAMID_AL2_MFA:
                        self.swamid_al2_used = True
                    elif cred.proofing_method == METHOD_SWAMID_AL2_MFA_HI:
                        self.swamid_al2_hi_used = True
            elif isinstance(cred, OnetimeCredential):
                logger.debug(f'External MFA used for this request: {cred}')
                self.external_mfa_used = True
                # TODO: Support more SwedenConnect authn contexts?
                if cred.authn_context == 'http://id.elegnamnden.se/loa/1.0/loa3':
                    self.swamid_al2_hi_used = True

        if user.nins.verified.to_list():
            self.is_swamid_al2 = True

    def __str__(self) -> str:
        return (
            f'<AuthnState: creds={len(self._creds)}, pw={self.password_used}, fido={self.fido_used}, '
            f'external_mfa={self.external_mfa_used}, nin is al2={self.is_swamid_al2}, '
            f'mfa is {self.is_multifactor} (al2={self.swamid_al2_used}, al2_hi={self.swamid_al2_hi_used})>'
        )

    @property
    def is_singlefactor(self) -> bool:
        return self.password_used or self.fido_used

    @property
    def is_multifactor(self) -> bool:
        return self.password_used and (self.fido_used or self.external_mfa_used)

    @property
    def is_swamid_al2_mfa(self) -> bool:
        return self.swamid_al2_used or self.swamid_al2_hi_used


def response_authn(ticket: SSOLoginData, user: IdPUser, sso_session: SSOSession) -> AuthnInfo:
    """
    Figure out what AuthnContext to assert in a SAML response,
    given the RequestedAuthnContext from the SAML request.

    :param req_authn_ctx: Requested authn context class
    """
    req_authn_ctx = get_requested_authn_context(ticket)

    authn = AuthnState(user, sso_session, ticket)
    logger.info(f'Authn for {user} will be evaluated based on: {authn}')

    SWAMID_AL1 = 'http://www.swamid.se/policy/assurance/al1'
    SWAMID_AL2 = 'http://www.swamid.se/policy/assurance/al2'
    SWAMID_AL2_MFA_HI = 'http://www.swamid.se/policy/authentication/swamid-al2-mfa-hi'

    attributes = {}
    response_authn = None

    if req_authn_ctx == EduidAuthnContextClass.REFEDS_MFA:
        current_idp_app.stats.count('req_authn_ctx_refeds_mfa')
        if not authn.password_used:
            raise MissingPasswordFactor()
        if not authn.is_multifactor:
            raise MissingMultiFactor()
        if not authn.is_swamid_al2_mfa:
            raise WrongMultiFactor()
        response_authn = EduidAuthnContextClass.REFEDS_MFA

    elif req_authn_ctx == EduidAuthnContextClass.REFEDS_SFA:
        current_idp_app.stats.count('req_authn_ctx_refeds_sfa')
        if not authn.is_singlefactor:
            raise MissingSingleFactor()
        response_authn = EduidAuthnContextClass.REFEDS_SFA

    elif req_authn_ctx == EduidAuthnContextClass.EDUID_MFA:
        current_idp_app.stats.count('req_authn_ctx_eduid_mfa')
        if not authn.password_used:
            raise MissingPasswordFactor()
        if not authn.is_multifactor:
            raise MissingMultiFactor()
        response_authn = EduidAuthnContextClass.EDUID_MFA

    elif req_authn_ctx == EduidAuthnContextClass.FIDO_U2F:
        current_idp_app.stats.count('req_authn_ctx_fido_u2f')
        if not authn.password_used and authn.fido_used:
            raise MissingMultiFactor()
        response_authn = EduidAuthnContextClass.FIDO_U2F

    elif req_authn_ctx == EduidAuthnContextClass.PASSWORD_PT:
        current_idp_app.stats.count('req_authn_ctx_password_pt')
        if authn.password_used:
            response_authn = EduidAuthnContextClass.PASSWORD_PT

    else:
        # Handle both unknown and empty req_authn_ctx the same
        if authn.is_multifactor:
            response_authn = EduidAuthnContextClass.REFEDS_MFA
        elif authn.password_used:
            response_authn = EduidAuthnContextClass.PASSWORD_PT

    if not response_authn:
        raise MissingAuthentication()

    if authn.is_swamid_al2:
        if authn.swamid_al2_hi_used and req_authn_ctx in [
            EduidAuthnContextClass.REFEDS_SFA,
            EduidAuthnContextClass.REFEDS_MFA,
        ]:
            attributes['eduPersonAssurance'] = [SWAMID_AL1, SWAMID_AL2, SWAMID_AL2_MFA_HI]
        else:
            attributes['eduPersonAssurance'] = [SWAMID_AL1, SWAMID_AL2]
    else:
        attributes['eduPersonAssurance'] = [SWAMID_AL1]

    logger.info(f'Assurances for {user} was evaluated to: {response_authn.name} with attributes {attributes}')

    authn_instant = int(sso_session.authn_timestamp.timestamp())

    return AuthnInfo(class_ref=response_authn.value, authn_attributes=attributes, instant=authn_instant)


def get_requested_authn_context(ticket: SSOLoginData) -> Optional[EduidAuthnContextClass]:
    """
    Check if the SP has explicit Authn preferences in the metadata (some SPs are not
    capable of conveying this preference in the RequestedAuthnContext)

    TODO: Don't just return the first one, but the most relevant somehow.
    """
    _accrs = ticket.saml_req.get_requested_authn_contexts()

    res = _pick_authn_context(_accrs, ticket.request_ref)

    attributes = ticket.saml_req.sp_entity_attributes
    if 'http://www.swamid.se/assurance-requirement' in attributes:
        # TODO: This is probably obsolete and not present anywhere in SWAMID metadata anymore
        new_authn = _pick_authn_context(attributes['http://www.swamid.se/assurance-requirement'], ticket.request_ref)
        current_app.logger.debug(
            f'Entity {ticket.saml_req.sp_entity_id} has AuthnCtx preferences in metadata. '
            f'Overriding {res} -> {new_authn}'
        )
        try:
            res = EduidAuthnContextClass(new_authn)
        except ValueError:
            logger.debug(f'Ignoring unknown authnContextClassRef found in metadata: {new_authn}')
    return res


def _pick_authn_context(accrs: Sequence[str], log_tag: str) -> Optional[EduidAuthnContextClass]:
    if len(accrs) > 1:
        logger.warning(f'{log_tag}: More than one authnContextClassRef, using the first recognised: {accrs}')
    # first, select the ones recognised by this IdP
    known = []
    for x in accrs:
        try:
            known += [EduidAuthnContextClass(x)]
        except ValueError:
            logger.debug(f'Ignoring unknown authnContextClassRef: {x}')
    if not known:
        return None
    # TODO: Pick the most applicable somehow, not just the first one in the list
    return known[0]
