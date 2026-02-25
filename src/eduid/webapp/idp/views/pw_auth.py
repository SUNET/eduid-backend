from flask import Blueprint, jsonify, request
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb.exceptions import UserOutOfSync
from eduid.userdb.idp.credential_user import CredentialUser
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.exceptions import EduidForbidden, EduidTooManyRequests
from eduid.webapp.common.api.messages import FluxData, error_response
from eduid.webapp.common.api.schemas.models import FluxSuccessResponse
from eduid.webapp.common.api.utils import save_and_sync_user
from eduid.webapp.common.session import session
from eduid.webapp.idp.app import current_idp_app as current_app
from eduid.webapp.idp.decorators import require_ticket, uses_sso_session
from eduid.webapp.idp.helpers import IdPMsg
from eduid.webapp.idp.idp_authn import AuthnData
from eduid.webapp.idp.login_context import LoginContext
from eduid.webapp.idp.mischttp import set_sso_cookie
from eduid.webapp.idp.schemas import PwAuthRequestSchema, PwAuthResponseSchema
from eduid.webapp.idp.sso_session import SSOSession, record_authentication

pw_auth_views = Blueprint("pw_auth", __name__, url_prefix="")


@pw_auth_views.route("/pw_auth", methods=["POST"])
@UnmarshalWith(PwAuthRequestSchema)
@MarshalWith(PwAuthResponseSchema)
@require_ticket
@uses_sso_session
def pw_auth(
    ticket: LoginContext, sso_session: SSOSession | None, password: str, username: str | None = None
) -> FluxData | WerkzeugResponse:
    current_app.logger.debug("\n\n")
    current_app.logger.debug(f"--- Password authentication ({ticket.request_ref}) ---")

    if not current_app.conf.login_bundle_url:
        return error_response(message=IdPMsg.not_available)

    if sso_session:
        username = sso_session.eppn
        current_app.logger.debug(f"Found eppn: {username} from SSO session")
    elif ticket.known_device and ticket.known_device.data.eppn:
        username = ticket.known_device.data.eppn
        current_app.logger.debug(f"Found eppn: {username} for known device ---")

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

    # Persist credential changes (e.g. v2 password upgrade) to the database
    if pwauth.credentials_changed:
        credential_user = CredentialUser.from_user(pwauth.user, current_app.credential_db)
        try:
            save_and_sync_user(
                credential_user,
                private_userdb=current_app.credential_db,
                app_name_override="eduid_idp",
            )
            current_app.logger.info(f"Saved credential changes for user {pwauth.user}")
        except UserOutOfSync:
            # Don't fail the login -- the upgrade will be retried on next authentication
            current_app.logger.warning(f"Failed to save credential changes for user {pwauth.user} (out of sync)")

    # Create/update SSO session
    current_app.logger.debug(f"User {pwauth.user} authenticated OK ({type(ticket)} request id {ticket.request_id})")
    _authn_credentials: list[AuthnData] = []
    if pwauth.authn_data:
        _authn_credentials = [pwauth.authn_data]
    sso_session = record_authentication(
        ticket, pwauth.user.eppn, sso_session, _authn_credentials, current_app.conf.sso_session_lifetime
    )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    current_app.logger.debug(f"Saving SSO session {sso_session}")
    current_app.sso_sessions.save(sso_session)

    # INFO-Log the request id and the sso_session
    authn_ref = ticket.get_requested_authn_context()
    current_app.logger.debug(f"Authenticating with {authn_ref!r}")

    current_app.logger.info(
        f"{ticket.request_ref}: login sso_session={sso_session.public_id}, authn={authn_ref}, user={pwauth.user}"
    )

    # Remember the password credential used for this particular request
    session.idp.log_credential_used(ticket.request_ref, pwauth.credential, pwauth.authn_data)

    # For debugging purposes, save the IdP SSO cookie value in the common session as well.
    # This is because we think we might have issues overwriting cookies in redirect responses.
    session.idp.sso_cookie_val = sso_session.session_id

    _flux_response = FluxSuccessResponse(request, payload={"finished": True})
    resp = jsonify(PwAuthResponseSchema().dump(_flux_response.to_dict()))

    return set_sso_cookie(current_app.conf.sso_cookie, sso_session.session_id, resp)
