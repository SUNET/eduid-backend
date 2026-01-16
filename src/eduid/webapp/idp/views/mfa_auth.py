from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from fido2.webauthn import AuthenticationResponse, UserVerificationRequirement
from flask import Blueprint, jsonify, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now
from eduid.common.models.saml2 import EduidAuthnContextClass
from eduid.userdb import User
from eduid.userdb.credentials import Credential
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response, success_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.authn import fido_tokens
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import MfaAction, RequestRef
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket, uses_sso_session
from eduid.webapp.idp.helpers import IdPMsg, lookup_user
from eduid.webapp.idp.idp_authn import AuthnData, ExternalAuthnData, FidoAuthnData
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.mischttp import set_sso_cookie
from eduid.webapp.idp.schemas import MfaAuthRequestSchema, MfaAuthResponseSchema
from eduid.webapp.idp.sso_session import SSOSession, record_authentication

mfa_auth_views = Blueprint("mfa_auth", __name__, url_prefix="")


@mfa_auth_views.route("/mfa_auth", methods=["POST"])
@UnmarshalWith(MfaAuthRequestSchema)
@MarshalWith(MfaAuthResponseSchema)
@require_ticket
@uses_sso_session
def mfa_auth(
    ticket: LoginContext, sso_session: SSOSession | None, webauthn_response: Mapping[str, str] | None = None
) -> FluxData | WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- MFA authentication ({ticket.request_ref}) ---")

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    _eppn = None
    if sso_session:
        _eppn = sso_session.eppn
        current_app.logger.debug(f"Found eppn: {_eppn} from SSO session")
        user = lookup_user(_eppn)
    elif ticket.known_device and ticket.known_device.data.eppn:
        _eppn = ticket.known_device.data.eppn
        current_app.logger.debug(f"Found eppn: {_eppn} for known device ---")
        user = lookup_user(_eppn)
    elif webauthn_response:
        current_app.logger.debug(f"Received WebAuthn response ({webauthn_response})")
        credential_id = webauthn_response.get("rawId")
        if isinstance(credential_id, str):
            user = current_app.userdb.get_user_by_credential(credential=credential_id)
            current_app.logger.debug(f"Found user: {user} for WebAuthn response")
    else:
        current_app.logger.debug("MFA auth called without an SSO session or known device")
        current_app.logger.debug("Creating open challenge for passkeys")
        return success_response(payload=_create_challenge(None, ticket))

    if not user:
        current_app.logger.error(f"User with eppn {_eppn} (from SSO session) not found")
        return error_response(message=IdPMsg.general_failure)

    # Clear mfa_action from session, so that we know if the user did external MFA
    # Yes - this should be done even if the user has FIDO credentials because the user might
    # opt to do external MFA anyway.
    saved_mfa_action = deepcopy(session.mfa_action)
    del session.mfa_action
    # setup new mfa_action for external mfa
    session.mfa_action.login_ref = ticket.request_ref
    session.mfa_action.eppn = user.eppn

    result = _check_external_mfa(saved_mfa_action, user, ticket.request_ref)
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
        payload: dict[str, Any] = _create_challenge(user, ticket)

        return success_response(payload=payload)

    if not result.authn_data or not result.credential:
        current_app.logger.error(f"No authn_data or credential in result: {result}")
        return error_response(message=IdPMsg.general_failure)

    current_app.logger.debug(f"AuthnData to save: {result.authn_data}")
    sso_session = record_authentication(
        ticket=ticket,
        eppn=user.eppn,
        sso_session=sso_session,
        credentials=[result.authn_data],
        sso_session_lifetime=current_app.conf.sso_session_lifetime,
    )
    current_app.logger.debug(f"Saving SSO session {sso_session}")
    current_app.sso_sessions.save(sso_session)

    current_app.authn.log_authn(user, success=[result.credential.key], failure=[])

    # Remember the MFA credential used for this particular request
    session.idp.log_credential_used(
        request_ref=ticket.request_ref, credential=result.credential, authn_data=result.authn_data
    )

    # For debugging purposes, save the IdP SSO cookie value in the common session as well.
    # This is because we think we might have issues overwriting cookies in redirect responses.
    session.idp.sso_cookie_val = sso_session.session_id

    _flux_response = FluxSuccessResponse(request, payload={"finished": True})
    resp = jsonify(MfaAuthResponseSchema().dump(_flux_response.to_dict()))

    return set_sso_cookie(current_app.conf.sso_cookie, sso_session.session_id, resp)


@dataclass
class CheckResult:
    response: FluxData | None = None
    credential: Credential | None = None
    authn_data: AuthnData | None = None


def _check_external_mfa(mfa_action: MfaAction, user: User, ref: RequestRef) -> CheckResult | None:
    # Third party service MFA
    if mfa_action.success is True:  # Explicit check that success is the boolean True
        if mfa_action.login_ref:
            # TODO: Make this an unconditional check once frontend has been updated to pass login_ref to
            #       the eidas /mfa-authenticate endpoint
            if mfa_action.login_ref != ref:
                current_app.logger.info("MFA data in session does not match this request, rejecting")
                return None

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
            auth_response=AuthenticationResponse.from_dict(webauthn_response),
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

    authn = AuthnData(
        cred_id=cred.key,
        timestamp=_utc_now,
        fido=FidoAuthnData(user_present=result.user_present, user_verified=result.user_verified),
    )
    return CheckResult(credential=cred, authn_data=authn)


def _create_challenge(user: User | None, ticket: LoginContext) -> dict[str, Any]:
    # If no external MFA was used, and no webauthn credential either, we respond with a not-finished
    # response containing a webauthn challenge if applicable.
    payload: dict[str, Any] = {"finished": False}

    # figure out which UserVerification we should ask for
    # if MFA is requested we should use PREFERRED as to hopefully get two factors directly
    # if anything else we will use DISCOURAGE as a single factor is enough
    req_authn_ctx = ticket.get_requested_authn_context()
    user_verification = UserVerificationRequirement.DISCOURAGED
    if any(ctx in {EduidAuthnContextClass.DIGG_LOA2, EduidAuthnContextClass.REFEDS_MFA} for ctx in req_authn_ctx):
        user_verification = UserVerificationRequirement.PREFERRED
    if user is None:
        # If we have no user, we prefer user verification
        # This triggers unlocking of hardware keys in Firefox
        user_verification = UserVerificationRequirement.PREFERRED

    current_app.logger.debug("User has one or more FIDO tokens, adding webauthn challenge to response")
    options = fido_tokens.start_token_verification(
        user=user,
        fido2_rp_id=current_app.conf.fido2_rp_id,
        fido2_rp_name=current_app.conf.fido2_rp_name,
        state=session.mfa_action,
        user_verification=user_verification,
    )
    payload.update(options)

    current_app.logger.debug("No MFA submitted. Sending not-finished response.")
    current_app.logger.debug(
        f"Will accept external MFA for login ref: {session.mfa_action.login_ref} and eppn: {session.mfa_action.eppn}"
    )
    return payload
