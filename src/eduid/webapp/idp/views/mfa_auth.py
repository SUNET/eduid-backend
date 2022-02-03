from copy import deepcopy
from typing import Any, Dict, Optional

from flask import Blueprint, request

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import FidoCredential
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.session import session
from eduid.webapp.common.session.logindata import ExternalMfaData
from eduid.webapp.common.session.namespaces import MfaActionError, OnetimeCredType, OnetimeCredential, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login import get_ticket
from eduid.webapp.idp.schemas import MfaAuthRequestSchema, MfaAuthResponseSchema
from eduid.webapp.idp.service import SAMLQueryParams

mfa_auth_views = Blueprint('mfa_auth', __name__, url_prefix='')


@mfa_auth_views.route('/mfa_auth', methods=['POST'])
@UnmarshalWith(MfaAuthRequestSchema)
@MarshalWith(MfaAuthResponseSchema)
def mfa_auth(ref: RequestRef, webauthn_response: Optional[Dict[str, str]] = None) -> FluxData:
    current_app.logger.debug('\n\n')
    current_app.logger.debug(f'--- MFA authentication ({request.method}) ---')

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _info = SAMLQueryParams(request_ref=ref)
    ticket = get_ticket(_info, None)
    if not ticket:
        return error_response(message=IdPMsg.bad_ref)

    sso_session = current_app._lookup_sso_session()
    if not sso_session:
        current_app.logger.error(f'MFA auth called without an SSO session')
        return error_response(message=IdPMsg.no_sso_session)

    user = current_app.central_userdb.lookup_user(sso_session.eppn)
    if not user:
        current_app.logger.error(f'User with eppn {sso_session.eppn} (from SSO session) not found')
        return error_response(message=IdPMsg.general_failure)

    # Clear mfa_action from session, so that we know if the user did external MFA
    # Yes - this should be done even if the user has FIDO credentials because the user might
    # opt to do external MFA anyways.
    saved_mfa_action = deepcopy(session.mfa_action)
    del session.mfa_action

    # Third party service MFA
    if saved_mfa_action.success is True:  # Explicit check that success is the boolean True
        current_app.logger.info(f'User {user} logged in using external MFA service {saved_mfa_action.issuer}')

        _utc_now = utc_now()

        # External MFA authentication
        sso_session.external_mfa = ExternalMfaData(
            issuer=saved_mfa_action.issuer, authn_context=saved_mfa_action.authn_context, timestamp=_utc_now
        )
        # Remember the MFA credential used for this particular request
        otc = OnetimeCredential(
            type=OnetimeCredType.external_mfa,
            issuer=sso_session.external_mfa.issuer,
            authn_context=sso_session.external_mfa.authn_context,
            timestamp=_utc_now,
        )
        session.idp.log_credential_used(ref, otc, _utc_now)

        return success_response(payload={'finished': True})

    # External MFA was tried and failed, mfa_action.error is set in the eidas app
    if saved_mfa_action.error is not None:
        if saved_mfa_action.error is MfaActionError.authn_context_mismatch:
            return error_response(message=IdPMsg.eidas_authn_context_mismatch)
        elif saved_mfa_action.error is MfaActionError.authn_too_old:
            return error_response(message=IdPMsg.eidas_reauthn_expired)
        elif saved_mfa_action.error is MfaActionError.nin_not_matching:
            return error_response(message=IdPMsg.eidas_nin_not_matching)
        else:
            current_app.logger.warning(f'eidas returned {saved_mfa_action.error} that did not match an error message')
            return error_response(message=IdPMsg.general_failure)

    #
    # No external MFA
    #
    if webauthn_response is None:
        payload: Dict[str, Any] = {'finished': False}

        candidates = user.credentials.filter(FidoCredential)
        if candidates:
            options = fido_tokens.start_token_verification(user, current_app.conf.fido2_rp_id, session.mfa_action)
            payload.update(options)

        return success_response(payload=payload)

    #
    # Process webauthn_response
    #
    if not saved_mfa_action.webauthn_state:
        current_app.logger.error(f'No active webauthn challenge found in the session, can\'t do verification')
        return error_response(message=IdPMsg.general_failure)

    try:
        result = fido_tokens.verify_webauthn(user, webauthn_response, current_app.conf.fido2_rp_id, saved_mfa_action)
    except fido_tokens.VerificationProblem:
        current_app.logger.exception('Webauthn verification failed')
        current_app.logger.debug(f'webauthn_response: {repr(webauthn_response)}')
        return error_response(message=IdPMsg.mfa_auth_failed)

    current_app.logger.debug(f'verify_webauthn result: {result}')

    if not result.success:
        return error_response(message=IdPMsg.mfa_auth_failed)

    _utc_now = utc_now()

    cred = user.credentials.find(result.credential_key)
    if not cred:
        current_app.logger.error(f'Could not find credential {result.credential_key} on user {user}')
        return error_response(message=IdPMsg.general_failure)

    authn = AuthnData(cred_id=result.credential_key, timestamp=_utc_now)
    sso_session.add_authn_credential(authn)
    current_app.logger.debug(f'AuthnData to save: {authn}')

    current_app.logger.debug(f'Saving SSO session {sso_session}')
    current_app.sso_sessions.save(sso_session)

    current_app.authn.log_authn(user, success=[result.credential_key], failure=[])

    # Remember the MFA credential used for this particular request
    session.idp.log_credential_used(ref, cred, _utc_now)

    return success_response(payload={'finished': True})
