from flask import Blueprint, jsonify, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.misc.timeutil import utc_now
from eduid.userdb.credentials import FidoCredential
from eduid.userdb.idp import IdPUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import FluxData, error_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import LoginApplication
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket, uses_sso_session
from eduid.webapp.idp.helpers import IdPMsg, lookup_user
from eduid.webapp.idp.idp_authn import AuthnData, FidoAuthnData
from eduid.webapp.idp.login_context import LoginContext, LoginContextSAML
from eduid.webapp.idp.mischttp import set_sso_cookie
from eduid.webapp.idp.schemas import PwAuthResponseSchema, SignupAuthRequestSchema
from eduid.webapp.idp.sso_session import SSOSession, record_authentication

__author__ = "lundberg"

signup_auth_views = Blueprint("signup_auth", __name__, url_prefix="")


@signup_auth_views.route("/signup_auth", methods=["POST"])
@UnmarshalWith(SignupAuthRequestSchema)
@MarshalWith(PwAuthResponseSchema)
@require_ticket
@uses_sso_session
def signup_auth(ticket: LoginContext, sso_session: SSOSession | None) -> FluxData | WerkzeugResponse:
    """Authenticate a user who just completed signup, using their signup credentials."""
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- Signup authentication ({ticket.request_ref}) ---")

    if not current_app.conf.allow_new_signup_logins:
        current_app.logger.info("New signup logins are not enabled")
        return error_response(message=IdPMsg.must_authenticate)

    if session.common.login_source != LoginApplication.signup:
        current_app.logger.info("login_source is not signup")
        return error_response(message=IdPMsg.must_authenticate)

    if not session.common.eppn:
        current_app.logger.info("No eppn in session")
        return error_response(message=IdPMsg.must_authenticate)

    if session.signup.user_created_at is None:
        current_app.logger.info("No user_created_at in signup session")
        return error_response(message=IdPMsg.must_authenticate)

    if session.signup.idp_request_ref != ticket.request_ref:
        current_app.logger.debug(
            f"Signup idp_request_ref {session.signup.idp_request_ref} != ticket {ticket.request_ref}"
        )
        return error_response(message=IdPMsg.must_authenticate)

    age = utc_now() - session.signup.user_created_at
    if age > current_app.conf.new_signup_authn_lifetime:
        current_app.logger.info(f"New signup too old ({age} > {current_app.conf.new_signup_authn_lifetime})")
        return error_response(message=IdPMsg.must_authenticate)

    if not isinstance(ticket, LoginContextSAML):
        current_app.logger.warning(f"ticket {ticket.request_ref} not a LoginContextSAML instance: {type(ticket)}")
        return error_response(message=IdPMsg.bad_ref)

    if ticket.reauthn_required:
        current_app.logger.info("SP requires ForceAuthn, not accepting new signup as authentication")
        return error_response(message=IdPMsg.must_authenticate)

    # All checks passed
    current_app.logger.info(f"Accepting new signup as authentication for {session.common.eppn}")

    user = lookup_user(session.common.eppn)
    if not user:
        current_app.logger.error(f"New signup user {session.common.eppn} not found")
        return error_response(message=IdPMsg.general_failure)

    # Register signup credentials on the pending request and build AuthnData list
    _authn_credentials = _register_signup_credentials(ticket, user)
    if not _authn_credentials:
        current_app.logger.error("No credentials found on new signup user")
        return error_response(message=IdPMsg.general_failure)

    # Create/update SSO session
    sso_session = record_authentication(
        ticket, session.common.eppn, sso_session, _authn_credentials, current_app.conf.sso_session_lifetime
    )
    current_app.logger.debug(f"Saving SSO session {sso_session}")
    current_app.sso_sessions.save(sso_session)

    session.idp.sso_cookie_val = sso_session.session_id

    current_app.logger.info(
        f"{ticket.request_ref}: signup_auth sso_session={sso_session.public_id}, user={session.common.eppn}"
    )
    current_app.stats.count("login_new_signup_accepted")

    _flux_response = FluxSuccessResponse(request, payload={"finished": True})
    resp = jsonify(PwAuthResponseSchema().dump(_flux_response.to_dict()))

    return set_sso_cookie(current_app.conf.sso_cookie, sso_session.session_id, resp)


def _register_signup_credentials(ticket: LoginContext, user: IdPUser) -> list[AuthnData]:
    """Register the user's signup credentials on the pending request and return AuthnData for the SSO session."""
    authn_credentials: list[AuthnData] = []
    assert session.signup.user_created_at is not None  # checked by caller

    for cred in user.credentials.to_list():
        fido_data = None
        if isinstance(cred, FidoCredential):
            # Use the signup session's webauthn data for user_verified if available
            wn = session.signup.credentials.webauthn
            fido_data = FidoAuthnData(
                user_present=wn.user_present if wn else True,
                user_verified=wn.user_verified if wn else False,
            )

        authn_data = AuthnData(
            cred_id=cred.key,
            timestamp=session.signup.user_created_at,
            fido=fido_data,
        )
        session.idp.log_credential_used(ticket.request_ref, cred, authn_data)
        authn_credentials.append(authn_data)

    return authn_credentials
