from flask import Blueprint, jsonify, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.exceptions import EduidForbidden, EduidTooManyRequests
from eduid.webapp.common.api.messages import FluxData, error_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.session import session
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.mischttp import set_sso_cookie
from eduid.webapp.idp.schemas import PwAuthRequestSchema, PwAuthResponseSchema
from eduid.webapp.idp.sso_session import record_authentication

pw_auth_views = Blueprint("pw_auth", __name__, url_prefix="")


@pw_auth_views.route("/pw_auth", methods=["POST"])
@UnmarshalWith(PwAuthRequestSchema)
@MarshalWith(PwAuthResponseSchema)
@require_ticket
def pw_auth(ticket: LoginContext, username: str, password: str) -> FluxData | WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- Password authentication ({ticket.request_ref}) ---")

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    if not username or not password:
        current_app.logger.debug("Credentials not supplied")
        return error_response(message=IdPMsg.wrong_credentials)

    try:
        pwauth = current_app.authn.password_authn(username, password)
    except EduidTooManyRequests:
        return error_response(message=IdPMsg.user_temporary_locked)
    except EduidForbidden as e:
        if e.args[0] == "CREDENTIAL_EXPIRED":
            return error_response(message=IdPMsg.credential_expired)
        return error_response(message=IdPMsg.wrong_credentials)
    finally:
        del password  # keep out of any exception logs

    if not pwauth:
        current_app.logger.info(f"{ticket.request_ref}: Password authentication failed")
        return error_response(message=IdPMsg.wrong_credentials)

    # Create/update SSO session
    current_app.logger.debug(f"User {pwauth.user} authenticated OK ({type(ticket)} request id {ticket.request_id})")
    _sso_session = current_app._lookup_sso_session()
    _authn_credentials: list[AuthnData] = []
    if pwauth.authndata:
        _authn_credentials = [pwauth.authndata]
    _sso_session = record_authentication(
        ticket, pwauth.user.eppn, _sso_session, _authn_credentials, current_app.conf.sso_session_lifetime
    )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    current_app.sso_sessions.save(_sso_session)

    # INFO-Log the request id and the sso_session
    authn_ref = ticket.get_requested_authn_context()
    current_app.logger.debug(f"Authenticating with {repr(authn_ref)}")

    current_app.logger.info(
        f"{ticket.request_ref}: login sso_session={_sso_session.public_id}, authn={authn_ref}, user={pwauth.user}"
    )

    # Remember the password credential used for this particular request
    session.idp.log_credential_used(ticket.request_ref, pwauth.credential, pwauth.timestamp)

    # For debugging purposes, save the IdP SSO cookie value in the common session as well.
    # This is because we think we might have issues overwriting cookies in redirect responses.
    session.idp.sso_cookie_val = _sso_session.session_id

    _flux_response = FluxSuccessResponse(request, payload={"finished": True})
    resp = jsonify(PwAuthResponseSchema().dump(_flux_response.to_dict()))

    return set_sso_cookie(current_app.conf.sso_cookie, _sso_session.session_id, resp)
