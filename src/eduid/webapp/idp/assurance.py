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

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import CredentialProofingMethod, FidoCredential, Password, Webauthn
from eduid.userdb.credentials.external import SwedenConnectCredential
from eduid.userdb.element import ElementKey
from eduid.userdb.idp import IdPUser
from eduid.webapp.common.session.namespaces import OnetimeCredential, OnetimeCredType
from eduid.webapp.idp.app import current_idp_app
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance_data import AuthnInfo, EduidAuthnContextClass, UsedCredential, UsedWhere
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.sso_session import SSOSession

logger = logging.getLogger(__name__)

"""
Assurance Level functionality.
"""


class AssuranceException(Exception):
    pass


class MissingSingleFactor(AssuranceException):
    pass


class MissingPasswordFactor(AssuranceException):
    pass


class MissingMultiFactor(AssuranceException):
    pass


class MissingAuthentication(AssuranceException):
    pass


class AuthnState:
    def __init__(self, user: IdPUser, sso_session: SSOSession, ticket: LoginContext):
        self.password_used = False
        self.is_swamid_al2 = False
        self.fido_used = False
        self.external_mfa_used = False
        self.swamid_al2_used = False
        self.swamid_al3_used = False
        self._onetime_credentials: dict[ElementKey, OnetimeCredential] = {}
        self._credentials = self._gather_credentials(sso_session, ticket, user)

        for this in self._credentials:
            cred = user.credentials.find(this.credential_id)
            if not cred:
                # check if it was a one-time credential
                cred = self._onetime_credentials.get(this.credential_id)
            if isinstance(cred, Password):
                self.password_used = True
            elif isinstance(cred, FidoCredential):
                self.fido_used = True
                if cred.is_verified:
                    if cred.proofing_method == CredentialProofingMethod.SWAMID_AL2_MFA:
                        self.swamid_al2_used = True
                    elif cred.proofing_method == CredentialProofingMethod.SWAMID_AL3_MFA:
                        self.swamid_al3_used = True
            elif isinstance(cred, OnetimeCredential):
                # OLD way
                logger.debug(f"External MFA used for this request: {cred}")
                self.external_mfa_used = True
                # TODO: Support more SwedenConnect authn contexts?
                if cred.authn_context == "http://id.elegnamnden.se/loa/1.0/loa3":
                    self.swamid_al3_used = True
            elif isinstance(cred, SwedenConnectCredential):
                # NEW way
                logger.debug(f"SwedenConnect MFA used for this request: {cred}")
                self.external_mfa_used = True
                if cred.level == "loa3":
                    self.swamid_al3_used = True
            else:
                # Warn, but do not fail when the credential isn't found on the user. This can't be a hard failure,
                # because when a user changes password they will get a new credential and the old is removed from
                # the user but the old one might still be referenced in the SSO session, or the session.
                logger.warning(f"Credential with id {this.credential_id} not found on user")
                _creds = user.credentials.to_list()
                logger.debug(f"User credentials:\n{_creds}")
                logger.debug(f"Session one-time credentials:\n{ticket.pending_request.onetime_credentials}")

        if user.identities.is_verified:
            self.is_swamid_al2 = True

    def _gather_credentials(self, sso_session: SSOSession, ticket: LoginContext, user: IdPUser) -> list[UsedCredential]:
        """
        Gather credentials used for authentication.

        Add all credentials used with this very request and then, unless the request has forceAuthn set,
        add credentials from the SSO session.
        """
        _used_credentials: dict[ElementKey, UsedCredential] = {}

        # Add all credentials used while the IdP processed this very request
        for key, ts in ticket.pending_request.credentials_used.items():
            if key in ticket.pending_request.onetime_credentials:
                onetime_cred = ticket.pending_request.onetime_credentials[key]
                cred = UsedCredential(credential_id=onetime_cred.key, ts=ts, source=UsedWhere.REQUEST)
            else:
                credential = user.credentials.find(key)
                if not credential:
                    logger.warning(f"Could not find credential {key} on user {user}")
                    continue
                cred = UsedCredential(credential_id=credential.key, ts=ts, source=UsedWhere.REQUEST)
            logger.debug(f"Adding credential used with this request: {cred}")
            _used_credentials[cred.credential_id] = cred

        _used_request = [x for x in _used_credentials.values() if x.source == UsedWhere.REQUEST]
        logger.debug(f"Number of credentials used with this very request: {len(_used_request)}")

        if ticket.reauthn_required:
            logger.debug("Request requires authentication, not even considering credentials from the SSO session")
            return list(_used_credentials.values())

        # Request does not have forceAuthn set, so gather credentials from the SSO session
        for this in sso_session.authn_credentials:
            credential = user.credentials.find(this.cred_id)
            if not credential:
                logger.warning(f"Could not find credential {this.cred_id} on user {user}")
                continue
            # TODO: The authn_timestamp in the SSO session is not necessarily right for all credentials there
            cred = UsedCredential(credential_id=credential.key, ts=sso_session.authn_timestamp, source=UsedWhere.SSO)
            _key = cred.credential_id
            if _key in _used_credentials:
                # If the credential is in _used_credentials, it is because it was used with this very request.
                continue
            logger.debug(f"Adding credential used from the SSO session: {cred}")
            _used_credentials[_key] = cred

        # External mfa check
        if sso_session.external_mfa is not None:
            logger.debug(f"External MFA (in SSO session) issuer: {sso_session.external_mfa.issuer}")
            logger.debug(f"External MFA (in SSO session) credential_id: {sso_session.external_mfa.credential_id}")

            # Check if there is an ExternalCredential on the user (the new way), or if we need to mint
            # a temporary OnetimeCredential.
            if not sso_session.external_mfa.credential_id:
                logger.debug("Creating temporary OnetimeCredential")
                _otc = OnetimeCredential(
                    authn_context=sso_session.external_mfa.authn_context,
                    issuer=sso_session.external_mfa.issuer,
                    timestamp=sso_session.external_mfa.timestamp,
                    type=OnetimeCredType.external_mfa,
                )
                self._onetime_credentials[_otc.key] = _otc
                cred = UsedCredential(credential_id=_otc.key, ts=sso_session.authn_timestamp, source=UsedWhere.SSO)
                _used_credentials[ElementKey("SSO_external_MFA")] = cred

        _used_sso = [x for x in _used_credentials.values() if x.source == UsedWhere.SSO]
        logger.debug(f"Number of credentials inherited from the SSO session: {len(_used_sso)}")

        return list(_used_credentials.values())

    def __str__(self) -> str:
        return (
            f"<AuthnState: creds={len(self._credentials)}, pw={self.password_used}, fido={self.fido_used}, "
            f"external_mfa={self.external_mfa_used}, nin is al2={self.is_swamid_al2}, "
            f"mfa is {self.is_multifactor} (al2={self.swamid_al2_used}, al3={self.swamid_al3_used})>"
        )

    @property
    def is_singlefactor(self) -> bool:
        return self.password_used or self.fido_used

    @property
    def is_multifactor(self) -> bool:
        return self.password_used and (self.fido_used or self.external_mfa_used)

    @property
    def credentials(self) -> list[UsedCredential]:
        # property to make the credentials read-only
        return self._credentials


def response_authn(authn: AuthnState, ticket: LoginContext, user: IdPUser, sso_session: SSOSession) -> AuthnInfo:
    """
    Figure out what AuthnContext to assert in a SAML response,
    given the RequestedAuthnContext from the SAML request.
    """
    req_authn_ctx = ticket.get_requested_authn_context()
    logger.info(f"Authn for {user} will be evaluated based on: {authn}")

    attributes = {}
    response_authn = None

    if req_authn_ctx == EduidAuthnContextClass.REFEDS_MFA:
        current_idp_app.stats.count("req_authn_ctx_refeds_mfa")
        if not authn.password_used:
            raise MissingPasswordFactor()
        if not authn.is_multifactor:
            raise MissingMultiFactor()
        response_authn = EduidAuthnContextClass.REFEDS_MFA

    elif req_authn_ctx == EduidAuthnContextClass.REFEDS_SFA:
        current_idp_app.stats.count("req_authn_ctx_refeds_sfa")
        if not authn.is_singlefactor:
            raise MissingSingleFactor()
        response_authn = EduidAuthnContextClass.REFEDS_SFA

    elif req_authn_ctx == EduidAuthnContextClass.EDUID_MFA:
        current_idp_app.stats.count("req_authn_ctx_eduid_mfa")
        if not authn.password_used:
            raise MissingPasswordFactor()
        if not authn.is_multifactor:
            raise MissingMultiFactor()
        response_authn = EduidAuthnContextClass.EDUID_MFA

    elif req_authn_ctx == EduidAuthnContextClass.FIDO_U2F:
        current_idp_app.stats.count("req_authn_ctx_fido_u2f")
        if not authn.password_used and authn.fido_used:
            raise MissingMultiFactor()
        response_authn = EduidAuthnContextClass.FIDO_U2F

    elif req_authn_ctx == EduidAuthnContextClass.PASSWORD_PT:
        current_idp_app.stats.count("req_authn_ctx_password_pt")
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
        if authn.swamid_al3_used and req_authn_ctx in [
            EduidAuthnContextClass.REFEDS_MFA,
        ]:
            attributes["eduPersonAssurance"] = [item.value for item in current_app.conf.swamid_assurance_profile_3]
        else:
            attributes["eduPersonAssurance"] = [item.value for item in current_app.conf.swamid_assurance_profile_2]
    else:
        attributes["eduPersonAssurance"] = [item.value for item in current_app.conf.swamid_assurance_profile_1]

    logger.info(f"Assurances for {user} was evaluated to: {response_authn.name} with attributes {attributes}")

    # From all the credentials we're basing this authentication on, use the earliest one as authn instant.
    _instant = utc_now()
    for this in authn.credentials:
        logger.debug(f"Credential {this.credential_id} ({this.source.value}) was used {this.ts.isoformat()}")
        if not _instant or this.ts < _instant:
            _instant = this.ts

    logger.debug(f"Authn instant: {_instant.isoformat()}")
    return AuthnInfo(class_ref=response_authn, authn_attributes=attributes, instant=_instant)
