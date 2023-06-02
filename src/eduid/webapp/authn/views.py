#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2020 SUNET
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
from dataclasses import dataclass
import uuid
from typing import Optional

from flask import Blueprint, abort, make_response, redirect, request
from saml2 import BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.ident import decode
from saml2.metadata import entity_descriptor
from saml2.saml import NAMEID_FORMAT_UNSPECIFIED, NameID, Subject
from saml2.request import AuthnRequest
from werkzeug.exceptions import Forbidden
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid.userdb.exceptions import MultipleUsersReturned, UserDoesNotExist
from eduid.webapp.authn import acs_actions  # acs_action needs to be imported to be loaded
from eduid.webapp.authn.app import current_authn_app as current_app
from eduid.webapp.authn.helpers import AuthnMsg
from eduid.webapp.authn.schemas import (
    AuthnAuthenticateRequestSchema,
    AuthnCommonResponseSchema,
    AuthnStatusRequestSchema,
    AuthnStatusResponseSchema,
)
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.messages import (
    CommonMsg,
    FluxData,
    TranslatableMsg,
    error_response,
    redirect_with_msg,
    success_response,
)
from eduid.webapp.common.api.utils import sanitise_redirect_url
from eduid.webapp.common.authn.acs_enums import AuthnAcsAction
from eduid.webapp.common.authn.acs_registry import ACSArgs, get_action
from eduid.webapp.common.authn.cache import IdentityCache, StateCache
from eduid.webapp.common.authn.eduid_saml2 import get_authn_request, process_assertion, saml_logout
from eduid.webapp.common.authn.utils import check_previous_identification, get_location
from eduid.webapp.common.session import EduidSession, session
from eduid.webapp.common.session.namespaces import AuthnRequestRef, LoginApplication, SP_AuthnRequest

assert acs_actions  # make sure nothing optimises away the import of this, as it is needed to execute @acs_actions

authn_views = Blueprint("authn", __name__, url_prefix="")

# use this as frontend_action to fall back to the old mechanism using redirect_url
FALLBACK_FRONTEND_ACTION = "fallback-redirect-url"


@authn_views.route("/login")
def login() -> WerkzeugResponse:
    """
    login view, redirects to SAML2 IdP
    """
    return _old_authn(AuthnAcsAction.login, same_user=False)


@authn_views.route("/reauthn")
def reauthn() -> WerkzeugResponse:
    """
    login view with force authn, redirects to SAML2 IdP
    """
    session.common.is_logged_in = False
    return _old_authn(AuthnAcsAction.reauthn, force_authn=True)


@authn_views.route("/chpass")
def chpass() -> WerkzeugResponse:
    """
    Reauthn view, sends a SAML2 reauthn request to the IdP.
    """
    return _old_authn(AuthnAcsAction.change_password, force_authn=True)


@authn_views.route("/terminate")
def terminate() -> WerkzeugResponse:
    """
    Reauthn view, sends a SAML2 reauthn request to the IdP.
    """
    return _old_authn(AuthnAcsAction.terminate_account, force_authn=True)


@authn_views.route("/authenticate", methods=["POST"])
@UnmarshalWith(AuthnAuthenticateRequestSchema)
@MarshalWith(AuthnCommonResponseSchema)
def authenticate(
    method: str,
    frontend_action: str,
    frontend_state: Optional[str] = None,
    same_user: Optional[bool] = None,
    force_authn: Optional[bool] = None,
) -> FluxData:
    current_app.logger.debug(f"authenticate called with frontend_action: {frontend_action}")

    # TODO: One idea would be for the backend to enforce the parameters needed for a certain frontend operation
    #       (such as re-authn before password change) here, instead of leaving it up to the frontend to know what
    #       the requirements will actually be for a certain operation, and fail to present an authentication that
    #       meets those requirements later.

    sp_authn = SP_AuthnRequest(
        post_authn_action=AuthnAcsAction.login,
        redirect_url=None,
        frontend_action=frontend_action,
        frontend_state=frontend_state,
        method=method,
    )

    result = _authn(sp_authn, force_authn=bool(force_authn), same_user=bool(same_user), idp=_get_idp())

    if result.error:
        return error_response(message=result.error)

    return success_response(payload={"location": result.url})


# get_status to not get tangled up in /status/healthy and the like
@authn_views.route("/get_status", methods=["POST"])
@UnmarshalWith(AuthnStatusRequestSchema)
@MarshalWith(AuthnStatusResponseSchema)
def get_status(authn_id: AuthnRequestRef) -> FluxData:
    authn = session.authn.sp.authns.get(authn_id)
    if not authn:
        return error_response(message=AuthnMsg.not_found)

    payload = {
        "authn_id": authn_id,
        "frontend_action": authn.frontend_action,
        "frontend_state": authn.frontend_state,
        "method": authn.method,
        "error": bool(authn.error),
    }
    if authn.status is not None:
        payload["status"] = authn.status

    return success_response(payload=payload)


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
    # TODO: Stop using the "next" parameter, because it opens up for redirect attacks.
    #       Instead, let frontend say "frontend_action=chpass" and we look up the finish_url
    #       for "chpass" in configuration.
    redirect_url = sanitise_redirect_url(request.args.get("next"), current_app.conf.saml2_login_redirect_url)
    frontend_action = request.args.get("frontend_action", FALLBACK_FRONTEND_ACTION)

    idp = _get_idp()

    # Be somewhat backwards compatible and check the provided IdP parameter
    _requested_idp = request.args.get("idp")
    if _requested_idp and _requested_idp != idp:
        current_app.logger.error(f"Requested IdP {_requested_idp} not allowed")
        # TODO: use goto_errors_response()
        raise Forbidden("Requested IdP not allowed")

    sp_authn = SP_AuthnRequest(post_authn_action=action, redirect_url=redirect_url, frontend_action=frontend_action)

    result = _authn(sp_authn, force_authn, same_user, idp)
    if not result.url:
        raise RuntimeError("No redirect URL returned from _authn")

    current_app.logger.debug(f"Redirecting user to the IdP: {result.url}")
    return redirect(result.url)


@dataclass
class AuthnResult:
    authn_id: Optional[AuthnRequestRef] = None
    error: Optional[TranslatableMsg] = None
    url: Optional[str] = None


def _authn(sp_authn: SP_AuthnRequest, force_authn: bool, same_user: bool, idp: str) -> AuthnResult:
    _authn_id = AuthnRequestRef(str(uuid.uuid4()))
    # Filter out any previous authns with the same post_authn_action, both to keep the size of the session
    # below an upper bound, and because we currently need to use the post_authn_action value to find the
    # authn data for a specific action.
    session.authn.sp.authns = {
        k: v for k, v in session.authn.sp.authns.items() if v.post_authn_action != sp_authn.post_authn_action
    }
    session.authn.sp.authns[_authn_id] = sp_authn

    subject = None
    if same_user:
        name_id = NameID(format=NAMEID_FORMAT_UNSPECIFIED, text=session.common.eppn)
        subject = Subject(name_id=name_id)
        current_app.logger.debug(f"Requesting re-login by the same user with {subject}")

    authn_request = get_authn_request(
        saml2_config=current_app.saml2_config,
        session=session,
        relay_state="",
        authn_id=_authn_id,
        selected_idp=idp,
        force_authn=force_authn,
        sign_alg=current_app.conf.authn_sign_alg,
        digest_alg=current_app.conf.authn_digest_alg,
        subject=subject,
    )
    current_app.logger.info(f"Redirecting the user to the IdP for {sp_authn}")
    current_app.logger.debug(f"Stored SP_AuthnRequest[{_authn_id}]: {session.authn.sp.authns[_authn_id]}")
    _idp_redirect_url = get_location(authn_request)
    return AuthnResult(authn_id=_authn_id, url=_idp_redirect_url)


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
    if args.authn_req.frontend_action == FALLBACK_FRONTEND_ACTION:
        # Redirect the user to the view they came from.
        # TODO: This way is deprecated, since it might be abused in redirect attacks. Better have
        #       a number of configured return-URLs in the backend config, and have the frontend
        #       choose which one will be used with the 'frontend_action'.
        finish_url = args.authn_req.redirect_url
    else:
        finish_url = current_app.conf.frontend_action_finish_url.get(args.authn_req.frontend_action)

    if not finish_url:
        # We _really_ shouldn't end up here because this same thing would have been done in the
        # starting views above.
        current_app.logger.warning(f"No finish_url for frontend_action {args.authn_req.frontend_action}")
        if not current_app.conf.errors_url_template:
            return make_response("Unknown frontend action", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.SAML_RESPONSE_FAIL,
            rp=current_app.saml2_config.entityid,
        )

    formatted_finish_url = finish_url.format(app_name=current_app.conf.app_name, authn_id=assertion.authn_req_ref)

    if not result.success:
        current_app.logger.info(f"SAML ACS action failed: {result.message}")
        # update session so this error can be retrieved from the /status endpoint
        _msg = result.message or CommonMsg.temp_problem
        args.authn_req.error = _msg.value
        # Including the error in the redirect URL is deprecated and should be removed once frontend stops using it
        return redirect_with_msg(formatted_finish_url, _msg, error=True)

    current_app.logger.debug(f"SAML ACS action successful")

    if result.response:
        current_app.logger.debug(f"SAML ACS action returned a response")
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


@authn_views.route("/signup-authn", methods=["GET", "POST"])
def signup_authn() -> WerkzeugResponse:
    current_app.logger.debug("Authenticating signing up user")
    location_on_fail = current_app.conf.signup_authn_failure_redirect_url
    location_on_success = current_app.conf.signup_authn_success_redirect_url

    eppn = check_previous_identification(session.signup)
    if eppn is not None:
        current_app.logger.info(f"Starting authentication for user from signup with eppn: {eppn})")
        try:
            user = current_app.central_userdb.get_user_by_eppn(eppn)
        except MultipleUsersReturned:
            current_app.logger.error(f"There are more than one user with eduPersonPrincipalName = {eppn}")
            return redirect(location_on_fail)
        except UserDoesNotExist:
            current_app.logger.error(f"No user with eduPersonPrincipalName = {eppn} found")
            return redirect(location_on_fail)

        if user.locked_identity.count > 0:
            # This user has previously verified their account and is not new, this should not happen.
            current_app.logger.error(f"Not new user {user} tried to log in using signup authn")
            return redirect(location_on_fail)
        session.common.eppn = user.eppn
        session.common.is_logged_in = True
        session.common.login_source = LoginApplication.signup

        response = redirect(location_on_success)
        current_app.logger.info(f"Successful authentication, redirecting user {user} to {location_on_success}")
        return response

    current_app.logger.info(f"Signup authn failed, redirecting user to {location_on_fail}")
    return redirect(location_on_fail)


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
