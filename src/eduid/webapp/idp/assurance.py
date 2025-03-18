#!/usr/bin/python

import logging

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb.credentials import CredentialProofingMethod, FidoCredential, Password
from eduid.userdb.credentials.external import BankIDCredential, SwedenConnectCredential
from eduid.userdb.element import ElementKey
from eduid.userdb.idp import IdPUser
from eduid.webapp.common.session.namespaces import OnetimeCredential, OnetimeCredType
from eduid.webapp.idp.app import current_idp_app
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.assurance_data import AuthnInfo, UsedCredential, UsedWhere
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


class AuthnContextNotSupported(AssuranceException):
    pass


class IdentityProofingMethodNotAllowed(AssuranceException):
    pass


class MfaProofingMethodNotAllowed(AssuranceException):
    pass


class AuthnState:
    def __init__(self, user: IdPUser, sso_session: SSOSession, ticket: LoginContext) -> None:
        self.password_used = False
        self.is_swamid_al2 = False
        self.is_digg_loa2 = False
        self.fido_used = False
        self.external_mfa_used = False
        self.swamid_al3_used = False
        self.digg_loa2_approved_identity = False
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
                if cred.is_verified and cred.proofing_method == CredentialProofingMethod.SWAMID_AL3_MFA:
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
            elif isinstance(cred, BankIDCredential):
                # NEW way
                logger.debug(f"BankID MFA used for this request: {cred}")
                self.external_mfa_used = True
                if cred.level == "uncertified-loa3":
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

        # check if the user can assert DIGG loa2
        if user.identities.nin and user.identities.nin.is_verified:
            identity_proofing_method = user.identities.nin.proofing_method
            # if the identity was verified before 2023-02, the proofing_method has not been set
            # this will be fixed when we start enforcing re-proofing of NINs
            if identity_proofing_method is None:
                identity_proofing_method = user.identities.nin.get_missing_proofing_method()
            # DIGG only allow the following methods for identity proofing
            self.digg_loa2_approved_identity = (
                identity_proofing_method in current_app.conf.digg_loa2_allowed_identity_proofing_methods
            )
            logger.debug(f"User NIN proofing method: {identity_proofing_method}")
            if self.digg_loa2_approved_identity and self.swamid_al3_used:
                logger.info("User can assert DIGG loa2")
                self.is_digg_loa2 = True

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

        req_authn_ctx = ticket.get_requested_authn_context()
        if ticket.reauthn_required or req_authn_ctx is EduidAuthnContextClass.DIGG_LOA2:
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
            f"mfa is {self.is_multifactor} (al3={self.swamid_al3_used})>"
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


def response_authn(authn: AuthnState, ticket: LoginContext, user: IdPUser) -> AuthnInfo:
    """
    Figure out what AuthnContext to assert in a SAML response,
    given the RequestedAuthnContext from the SAML request.
    """
    req_authn_ctx = ticket.get_requested_authn_context()
    logger.info(f"Authn for {user} will be evaluated for {req_authn_ctx} based on: {authn}")

    attributes = {}
    response_accr = None

    if req_authn_ctx == EduidAuthnContextClass.DIGG_LOA2:
        current_idp_app.stats.count("req_authn_ctx_digg_loa2")
        if not authn.password_used:
            raise MissingPasswordFactor()
        if not authn.is_multifactor:
            raise MissingMultiFactor()
        if not authn.digg_loa2_approved_identity:
            raise IdentityProofingMethodNotAllowed()
        if not authn.swamid_al3_used:
            raise MfaProofingMethodNotAllowed()
        if not authn.is_digg_loa2:  # this case should be covered by the previous two, but belt and bracers
            raise AssuranceException()
        response_accr = EduidAuthnContextClass.DIGG_LOA2

    elif req_authn_ctx == EduidAuthnContextClass.REFEDS_MFA:
        current_idp_app.stats.count("req_authn_ctx_refeds_mfa")
        if not authn.password_used:
            raise MissingPasswordFactor()
        if not authn.is_multifactor:
            raise MissingMultiFactor()
        response_accr = EduidAuthnContextClass.REFEDS_MFA

    elif req_authn_ctx == EduidAuthnContextClass.REFEDS_SFA:
        current_idp_app.stats.count("req_authn_ctx_refeds_sfa")
        if not authn.is_singlefactor:
            raise MissingSingleFactor()
        response_accr = EduidAuthnContextClass.REFEDS_SFA

    elif req_authn_ctx == EduidAuthnContextClass.EDUID_MFA:
        current_idp_app.stats.count("req_authn_ctx_eduid_mfa")
        if not authn.password_used:
            raise MissingPasswordFactor()
        if not authn.is_multifactor:
            raise MissingMultiFactor()
        response_accr = EduidAuthnContextClass.EDUID_MFA

    elif req_authn_ctx == EduidAuthnContextClass.FIDO_U2F:
        current_idp_app.stats.count("req_authn_ctx_fido_u2f")
        if not authn.password_used and authn.fido_used:
            raise MissingMultiFactor()
        response_accr = EduidAuthnContextClass.FIDO_U2F

    elif req_authn_ctx == EduidAuthnContextClass.PASSWORD_PT:
        current_idp_app.stats.count("req_authn_ctx_password_pt")
        if not authn.password_used:
            raise MissingPasswordFactor()
        response_accr = EduidAuthnContextClass.PASSWORD_PT

    elif req_authn_ctx is None:
        # Handle empty req_authn_ctx
        if authn.is_multifactor:
            response_accr = EduidAuthnContextClass.REFEDS_MFA
        elif authn.password_used:
            response_accr = EduidAuthnContextClass.PASSWORD_PT
        else:
            raise MissingAuthentication()

    if response_accr is None:
        # Fail on unknown req_authn_ctx
        raise AuthnContextNotSupported()

    if authn.is_swamid_al2:
        if authn.swamid_al3_used:
            attributes["eduPersonAssurance"] = [item.value for item in current_app.conf.swamid_assurance_profile_3]
        else:
            attributes["eduPersonAssurance"] = [item.value for item in current_app.conf.swamid_assurance_profile_2]
    else:
        attributes["eduPersonAssurance"] = [item.value for item in current_app.conf.swamid_assurance_profile_1]

    logger.info(f"Assurances for {user} was evaluated to: {response_accr.name} with attributes {attributes}")

    # From all the credentials we're basing this authentication on, use the earliest one as authn instant.
    _instant = utc_now()
    for this in authn.credentials:
        logger.debug(f"Credential {this.credential_id} ({this.source.value}) was used {this.ts.isoformat()}")
        if not _instant or this.ts < _instant:
            _instant = this.ts

    logger.debug(f"Authn instant: {_instant.isoformat()}")
    return AuthnInfo(class_ref=response_accr, authn_attributes=attributes, instant=_instant)
