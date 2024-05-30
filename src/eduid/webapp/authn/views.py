from dataclasses import dataclass
from typing import Optional

from flask import Blueprint, abort, make_response, redirect, request
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.ident import decode
from saml2.metadata import entity_descriptor
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, NameID, Subject
from werkzeug.exceptions import Forbidden
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.common.config.base import AuthnParameters, FrontendAction
from eduid.common.decorators import deprecated
from eduid.userdb.credentials.fido import FidoCredential
from eduid.userdb.exceptions import UserDoesNotExist
from eduid.webapp.authn import acs_actions  # acs_action needs to be imported to be loaded
from eduid.webapp.authn.app import current_authn_app as current_app
from eduid.webapp.authn.helpers import AuthnMsg
from eduid.webapp.authn.schemas import AuthnCommonRequestSchema, AuthnCommonResponseSchema
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.messages import (
    AuthnStatusMsg,
    CommonMsg,
    FluxData,
    TranslatableMsg,
    error_response,
    redirect_with_msg,
    success_response,
)
from eduid.webapp.common.api.schemas.authn_status import StatusRequestSchema, StatusResponseSchema
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, get_action
from eduid.webapp.common.authn.cache import IdentityCache, StateCache
from eduid.webapp.common.authn.eduid_saml2 import get_authn_request, process_assertion, saml_logout
from eduid.webapp.common.authn.utils import get_location
from eduid.webapp.common.session import EduidSession, session
from eduid.webapp.common.session.namespaces import AuthnRequestRef, SP_AuthnRequest

assert acs_actions  # make sure nothing optimises away the import of this, as it is needed to execute @acs_actions

authn_views = Blueprint("authn", __name__, url_prefix="")

REFEDS_MFA = "https://refeds.org/profile/mfa"


# get-status to not get tangled up in /status/healthy and the like
@authn_views.route("/get-status", methods=["POST"])
@UnmarshalWith(StatusRequestSchema)
@MarshalWith(StatusResponseSchema)
def get_status(authn_id: AuthnRequestRef) -> FluxData:
    authn = session.authn.sp.authns.get(authn_id)
    if not authn:
        return error_response(message=AuthnStatusMsg.not_found)

    payload = {
        "frontend_action": authn.frontend_action.value,
        "frontend_state": authn.frontend_state,
        "method": authn.method,
        "error": bool(authn.error),
    }
    if authn.status is not None:
        payload["status"] = authn.status

    return success_response(payload=payload)


@deprecated("login view is deprecated, use authenticate view instead")
@authn_views.route("/login")
def login() -> WerkzeugResponse:
    """
    login view, redirects to SAML2 IdP
    """
    return _old_authn(AuthnAcsAction.login, same_user=False)


@deprecated("reauthn view is deprecated, use authenticate view instead")
@authn_views.route("/reauthn")
def reauthn() -> WerkzeugResponse:
    """
    login view with force authn, redirects to SAML2 IdP
    """
    session.common.is_logged_in = False
    return _old_authn(AuthnAcsAction.reauthn, force_authn=True)


@deprecated("chpass view is deprecated, use authenticate view instead")
@authn_views.route("/chpass")
def chpass() -> WerkzeugResponse:
    """
    Reauthn view, sends a SAML2 reauthn request to the IdP.
    """
    return _old_authn(AuthnAcsAction.change_password, force_authn=True)


@deprecated("terminate view is deprecated, use authenticate view instead")
@authn_views.route("/terminate")
def terminate() -> WerkzeugResponse:
    """
    Reauthn view, sends a SAML2 reauthn request to the IdP.
    """
    return _old_authn(AuthnAcsAction.terminate_account, force_authn=True)


@authn_views.route("/authenticate", methods=["POST"])
@UnmarshalWith(AuthnCommonRequestSchema)
@MarshalWith(AuthnCommonResponseSchema)
def authenticate(
    frontend_action: str,
    frontend_state: Optional[str] = None,
    method: Optional[str] = None,
) -> FluxData:
    current_app.logger.debug(f"authenticate called with frontend_action: {frontend_action}")
    try:
        action = FrontendAction(frontend_action)
        authn_params = current_app.conf.frontend_action_authn_parameters[action]
    except (ValueError, KeyError):
        current_app.logger.exception(f"Frontend action {frontend_action} not supported")
        return error_response(message=AuthnMsg.frontend_action_not_supported)

    req_authn_ctx = []
    _request_mfa = False
    if authn_params.high_security:
        if session.common.eppn:
            user = current_app.central_userdb.get_user_by_eppn(session.common.eppn)
            if user.credentials.filter(FidoCredential):
                _request_mfa = True
        current_app.logger.debug(
            f"High security authentication for user user {session.common.eppn} requested, available: {_request_mfa}"
        )

    if authn_params.force_mfa or _request_mfa:
        req_authn_ctx = [REFEDS_MFA]

    sp_authn = SP_AuthnRequest(
        post_authn_action=AuthnAcsAction.login,
        frontend_action=action,
        frontend_state=frontend_state,
        method=method,
        req_authn_ctx=req_authn_ctx,
        finish_url=authn_params.finish_url,
    )

    result = _authn(sp_authn, idp=_get_idp(), authn_params=authn_params)

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


def _get_idp() -> str:
    # In the future, we might want to support choosing the IdP somehow but for now
    # the only supported configuration is one (1) IdP.
    _configured_idps = current_app.saml2_config.getattr("idp")
    if len(_configured_idps) != 1:
        current_app.logger.error(f"Unknown SAML2 idp config: {repr(_configured_idps)}")
        # TODO: use goto_errors_response()
        raise RuntimeError("Unknown SAML2 idp config")
    # For now, we will only ever use the single configured IdP
    idp = list(_configured_idps.keys())[0]
    assert isinstance(idp, str)
    return idp


def _old_authn(action: AuthnAcsAction, force_authn: bool = False, same_user: bool = True) -> WerkzeugResponse:
    _frontend_action = request.args.get("frontend_action", FrontendAction.OLD_LOGIN)
    _next = request.args.get("next")
    try:
        frontend_action = FrontendAction(_frontend_action)
        authn_params = current_app.conf.frontend_action_authn_parameters[frontend_action]
    except (ValueError, KeyError):
        current_app.logger.exception(f"Frontend action {_frontend_action} not supported")
        raise Forbidden("Requested frontend action not supported")

    # allow backwards compatability authn_params
    authn_params.force_mfa = force_authn
    authn_params.same_user = same_user
    if _next:
        authn_params.finish_url = sanitise_redirect_url(_next)

    idp = _get_idp()

    # Be somewhat backwards compatible and check the provided IdP parameter
    _requested_idp = request.args.get("idp")
    if _requested_idp and _requested_idp != idp:
        current_app.logger.error(f"Requested IdP {_requested_idp} not allowed")
        # TODO: use goto_errors_response()
        raise Forbidden("Requested IdP not allowed")

    sp_authn = SP_AuthnRequest(
        post_authn_action=action,
        frontend_action=frontend_action,
        finish_url=authn_params.finish_url,
    )

    result = _authn(sp_authn, idp, authn_params)
    if not result.url:
        raise RuntimeError("No redirect URL returned from _authn")

    current_app.logger.debug(f"Redirecting user to the IdP: {result.url}")
    return redirect(result.url)


@dataclass
class AuthnResult:
    authn_id: Optional[AuthnRequestRef] = None
    error: Optional[TranslatableMsg] = None
    url: Optional[str] = None


def _authn(sp_authn: SP_AuthnRequest, idp: str, authn_params: AuthnParameters) -> AuthnResult:
    # Filter out any previous authns with the same frontend_action because we need to use the frontend_action value to
    # find the authn data for a specific action.
    session.authn.sp.authns = {
        k: v for k, v in session.authn.sp.authns.items() if v.frontend_action != sp_authn.frontend_action
    }
    session.authn.sp.authns[sp_authn.authn_id] = sp_authn

    subject = None
    if authn_params.same_user:
        name_id = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=session.common.eppn)
        subject = Subject(name_id=name_id)
        current_app.logger.debug(f"Requesting re-login by the same user with {subject}")

    authn_request = get_authn_request(
        saml2_config=current_app.saml2_config,
        session=session,
        relay_state="",
        authn_id=sp_authn.authn_id,
        selected_idp=idp,
        force_authn=authn_params.force_authn,
        sign_alg=current_app.conf.authn_sign_alg,
        digest_alg=current_app.conf.authn_digest_alg,
        subject=subject,
    )
    current_app.logger.info(f"Redirecting the user to the IdP for {sp_authn}")
    current_app.logger.debug(
        f"Stored SP_AuthnRequest[{sp_authn.authn_id}]: {session.authn.sp.authns[sp_authn.authn_id]}"
    )
    _idp_redirect_url = get_location(authn_request)
    return AuthnResult(authn_id=sp_authn.authn_id, url=_idp_redirect_url)


@authn_views.route("/saml2-acs", methods=["POST"])
def assertion_consumer_service() -> WerkzeugResponse:
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    assertion = process_assertion(
        form=request.form,
        sp_data=session.authn.sp,
        strip_suffix=current_app.conf.saml2_strip_saml_user_suffix,
    )
    if isinstance(assertion, WerkzeugResponse):
        return assertion
    current_app.logger.debug(f"Auth response:\n{assertion}\n\n")

    action = get_action(default_action=AuthnAcsAction.login, authndata=assertion.authndata)
    args = ACSArgs(
        session_info=assertion.session_info,
        authn_req=assertion.authndata,
        user=assertion.user,
    )
    result = action(args)
    current_app.logger.debug(f"ACS action result: {result}")

    assert isinstance(args.authn_req, SP_AuthnRequest)  # please mypy
    formatted_finish_url = args.authn_req.formatted_finish_url(app_name=current_app.conf.app_name)

    if not result.success:
        current_app.logger.info(f"SAML ACS action failed: {result.message}")
        # update session so this error can be retrieved from the /status endpoint
        _msg = result.message or CommonMsg.temp_problem
        args.authn_req.error = _msg.value
        # Including the error in the redirect URL is deprecated and should be removed once frontend stops using it
        return redirect_with_msg(formatted_finish_url, _msg, error=True)

    current_app.logger.debug("SAML ACS action successful")

    if result.response:
        current_app.logger.debug("SAML ACS action returned a response")
        return result.response

    return redirect(formatted_finish_url)


def _get_authn_name_id(session: EduidSession) -> Optional[NameID]:
    """
    Get the SAML2 NameID of the currently logged-in user.
    :param session: The current session object
    :return: NameID
    """
    if not session.authn.name_id:
        return None
    try:
        return decode(session.authn.name_id)
    except KeyError:
        return None


@authn_views.route("/logout", methods=["GET"])
def logout() -> WerkzeugResponse:
    """
    SAML Logout Request initiator.
    This view initiates the SAML2 Logout request
    using the pysaml2 library to create the LogoutRequest.
    """
    eppn = session.common.eppn

    location = request.args.get("next", current_app.conf.saml2_logout_redirect_url)

    if eppn is None:
        current_app.logger.info("Session cookie has expired, no logout action needed")
        return redirect(location)

    try:
        user = current_app.central_userdb.get_user_by_eppn(eppn)
    except UserDoesNotExist:
        current_app.logger.error(f"User {eppn} not found, no logout action needed")
        return redirect(location)

    current_app.logger.debug(f"Logout process started for user {user}")

    return saml_logout(current_app.saml2_config, user, location)


@authn_views.route("/saml2-ls", methods=["POST"])
def logout_service() -> WerkzeugResponse:
    """SAML Logout Response endpoint
    The IdP will send the logout response to this view,
    which will process it with pysaml2 help and log the user
    out.
    Note that the IdP can request a logout even when
    we didn't initiate the process as a single logout
    request started by another SP.
    """
    current_app.logger.debug("Logout service started")

    state = StateCache(session.authn.sp.pysaml2_dicts)
    identity = IdentityCache(session.authn.sp.pysaml2_dicts)
    client = Saml2Client(current_app.saml2_config, state_cache=state, identity_cache=identity)

    # Pick a 'next' destination from these alternatives (most preferred first):
    #   - RelayState from request.form
    #   - saml2_logout_redirect_url from config
    logout_redirect_url = current_app.conf.saml2_logout_redirect_url
    _next_page = request.form.get("RelayState") or logout_redirect_url
    # Since the chosen destination is possibly user input, it must be sanitised.
    next_page = sanitise_redirect_url(_next_page, logout_redirect_url)

    if "SAMLResponse" in request.form:  # we started the logout
        current_app.logger.debug("Receiving a logout response from the IdP")
        response = client.parse_logout_request_response(request.form["SAMLResponse"], BINDING_HTTP_REDIRECT)
        if response and response.status_ok():
            session.clear()
            return redirect(next_page)
        else:
            current_app.logger.error("Unknown error during the logout")
            abort(400)

    # logout started by the IdP
    elif "SAMLRequest" in request.form:
        current_app.logger.debug("Receiving a logout request from the IdP")
        subject_id = _get_authn_name_id(session)
        if subject_id is None:
            current_app.logger.warning(
                f"The session does not contain the subject id for user {session.common.eppn}, performing local logout"
            )
            session.clear()
            return redirect(next_page)
        current_app.logger.debug(f"Logging out user using name-id from session: {subject_id}")
        http_info = client.handle_logout_request(
            request.form["SAMLRequest"], subject_id, BINDING_HTTP_REDIRECT, relay_state=request.form["RelayState"]
        )
        session.clear()
        location = get_location(http_info)
        # location comes from federation metadata and must be considered trusted, no need to sanitise
        current_app.logger.debug(f"Returning redirect to IdP SLO service: {location}")
        return redirect(location)
    current_app.logger.error("No SAMLResponse or SAMLRequest parameter found")
    abort(400)


@authn_views.route("/saml2-metadata")
def metadata() -> WerkzeugResponse:
    """
    Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the saml2_settings.py file.
    """
    metadata = entity_descriptor(current_app.saml2_config)
    response = make_response(metadata.to_string(), 200)
    response.headers["Content-Type"] = "text/xml; charset=utf8"
    return response
