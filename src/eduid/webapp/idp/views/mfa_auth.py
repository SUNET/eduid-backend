from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from flask import Blueprint

from eduid.common.misc.timeutil import utc_now
from eduid.userdb import User
from eduid.userdb.credentials import Credential, FidoCredential
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.session import EduidSession, session
from eduid.webapp.common.session.logindata import ExternalMfaData
from eduid.webapp.common.session.namespaces import MfaAction, OnetimeCredential, OnetimeCredType, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket, uses_sso_session
from eduid.webapp.idp.helpers import IdPMsg, lookup_user
from eduid.webapp.idp.idp_authn import AuthnData, ExternalAuthnData
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.schemas import MfaAuthRequestSchema, MfaAuthResponseSchema
from eduid.webapp.idp.sso_session import SSOSession

mfa_auth_views = Blueprint("mfa_auth", __name__, url_prefix="")


@mfa_auth_views.route("/mfa_auth", methods=["POST"])
@UnmarshalWith(MfaAuthRequestSchema)
@MarshalWith(MfaAuthResponseSchema)
@require_ticket
@uses_sso_session
def mfa_auth(
    ticket: LoginContext, sso_session: SSOSession | None, webauthn_response: Mapping[str, str] | None = None
) -> FluxData:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- MFA authentication ({ticket.request_ref}) ---")

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    if not sso_session:
        current_app.logger.error("MFA auth called without an SSO session")
        return error_response(message=IdPMsg.no_sso_session)

    user = lookup_user(sso_session.eppn)
    if not user:
        current_app.logger.error(f"User with eppn {sso_session.eppn} (from SSO session) not found")
        return error_response(message=IdPMsg.general_failure)

    # Clear mfa_action from session, so that we know if the user did external MFA
    # Yes - this should be done even if the user has FIDO credentials because the user might
    # opt to do external MFA anyway.
    saved_mfa_action = deepcopy(session.mfa_action)
    del session.mfa_action

    result = _check_external_mfa(saved_mfa_action, session, user, ticket.request_ref, sso_session)
    if result and result.response:
        return result.response

    if not result:
        # No external MFA
        result = _check_webauthn(webauthn_response, saved_mfa_action, user)
        if result and result.response:
            return result.response

    if not result:
        # If no external MFA was used, and no webauthn credential either, we respond with a not-finished
        # response containing a webauthn challenge if applicable.
        payload: dict[str, Any] = {"finished": False}

        candidates = user.credentials.filter(FidoCredential)
        if candidates:
            current_app.logger.debug("User has one or more FIDO tokens, adding webauthn challenge to response")
            options = fido_tokens.start_token_verification(
                user=user,
                fido2_rp_id=current_app.conf.fido2_rp_id,
                fido2_rp_name=current_app.conf.fido2_rp_name,
                state=session.mfa_action,
            )
            payload.update(options)

        current_app.logger.debug("No MFA submitted. Sending not-finished response.")
        return success_response(payload=payload)

    if not result.authn_data or not result.credential:
        current_app.logger.error(f"No authn_data or credential in result: {result}")
        return error_response(message=IdPMsg.general_failure)

    current_app.logger.debug(f"AuthnData to save: {result.authn_data}")
    sso_session.add_authn_credential(result.authn_data)
    current_app.logger.debug(f"Saving SSO session {sso_session}")
    current_app.sso_sessions.save(sso_session)

    current_app.authn.log_authn(user, success=[result.credential.key], failure=[])

    # Remember the MFA credential used for this particular request
    session.idp.log_credential_used(ticket.request_ref, result.credential, result.authn_data.timestamp)

    return success_response(payload={"finished": True})


@dataclass
class CheckResult:
    response: FluxData | None = None
    credential: Credential | None = None
    authn_data: AuthnData | None = None


def _check_external_mfa(
    mfa_action: MfaAction, session: EduidSession, user: User, ref: RequestRef, sso_session: SSOSession
) -> CheckResult | None:
    # Third party service MFA
    if mfa_action.success is True:  # Explicit check that success is the boolean True
        if mfa_action.login_ref:
            # TODO: Make this an unconditional check once frontend has been updated to pass login_ref to
            #       the eidas /mfa-authenticate endpoint
            if mfa_action.login_ref != ref:
                current_app.logger.info("MFA data in session does not match this request, rejecting")
                return CheckResult(response=error_response(message=IdPMsg.general_failure))

        current_app.logger.info(f"User {user} logged in using external MFA service {mfa_action.issuer}")

        _utc_now = utc_now()
        cred = user.credentials.find(mfa_action.credential_used)
        if not cred:
            current_app.logger.info(f"MFA action credential used not found on user: {mfa_action.credential_used}")
            return None

        authn = AuthnData(
            cred_id=cred.key,
            timestamp=_utc_now,
            external=ExternalAuthnData(issuer=mfa_action.issuer, authn_context=mfa_action.authn_context),
        )

        current_app.logger.debug(f"Logging credential used in session: {cred}")
        session.idp.log_credential_used(request_ref=ref, credential=cred, authn_data=authn)

        return CheckResult(credential=cred, authn_data=authn)

    return None


def _check_webauthn(
    webauthn_response: Mapping[str, str] | None, mfa_action: MfaAction, user: User
) -> CheckResult | None:
    if webauthn_response is None:
        return None

    #
    # Process webauthn_response
    #
    if not mfa_action.webauthn_state:
        current_app.logger.error("No active webauthn challenge found in the session, can't do verification")
        return CheckResult(response=error_response(message=IdPMsg.general_failure))

    try:
        result = fido_tokens.verify_webauthn(
            user=user,
            request_dict=webauthn_response,
            rp_id=current_app.conf.fido2_rp_id,
            rp_name=current_app.conf.fido2_rp_name,
            state=mfa_action,
        )
    except fido_tokens.VerificationProblem:
        current_app.logger.exception("Webauthn verification failed")
        current_app.logger.debug(f"webauthn_response: {repr(webauthn_response)}")
        return CheckResult(response=error_response(message=IdPMsg.mfa_auth_failed))

    current_app.logger.debug(f"verify_webauthn result: {result}")

    if not result.success:
        return CheckResult(response=error_response(message=IdPMsg.mfa_auth_failed))

    cred = user.credentials.find(result.credential_key)
    if not cred:
        current_app.logger.error(f"Could not find credential {result.credential_key} on user {user}")
        return CheckResult(response=error_response(message=IdPMsg.general_failure))

    _utc_now = utc_now()

    authn = AuthnData(cred_id=cred.key, timestamp=_utc_now)
    return CheckResult(credential=cred, authn_data=authn)
