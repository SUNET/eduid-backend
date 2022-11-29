# -*- coding: utf-8 -*-
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, urlparse

from authlib.integrations.base_client import OAuthError
from flask import Blueprint, make_response, redirect, request, url_for
from werkzeug import Response as WerkzeugResponse
from werkzeug.exceptions import BadRequestKeyError

from eduid.userdb import User
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.authn.acs_registry import ACSArgs, get_action
from eduid.webapp.common.proofing.methods import get_proofing_method
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import OIDCState, RP_AuthnRequest
from eduid.webapp.svipe_id.app import current_svipe_id_app as current_app
from eduid.webapp.svipe_id.callback_enums import SvipeIDAction
from eduid.webapp.svipe_id.helpers import SvipeIDMsg
from eduid.webapp.svipe_id.schemas import (
    SvipeIDCommonRequestSchema,
    SvipeIDCommonResponseSchema,
    SvipeIDStatusRequestSchema,
    SvipeIDStatusResponseSchema,
)

__author__ = "lundberg"


svipe_id_views = Blueprint("svipe_id", __name__, url_prefix="")


@svipe_id_views.route("/", methods=["GET"])
@MarshalWith(EmptyResponse)
@require_user
def index(user: User) -> FluxData:
    return success_response(payload=None, message=None)


@svipe_id_views.route("/get_status", methods=["POST"])
@UnmarshalWith(SvipeIDStatusRequestSchema)
@MarshalWith(SvipeIDStatusResponseSchema)
def get_status(authn_id: OIDCState) -> FluxData:
    authn = session.svipe_id.rp.authns.get(authn_id)
    if not authn:
        return error_response(message=SvipeIDMsg.not_found)

    payload = {
        "frontend_action": authn.frontend_action,
        "frontend_state": authn.frontend_state,
        "method": authn.method,
        "error": bool(authn.error),
    }
    if authn.status is not None:
        payload["status"] = authn.status

    return success_response(payload=payload)


@svipe_id_views.route("/verify-identity", methods=["POST"])
@UnmarshalWith(SvipeIDCommonRequestSchema)
@MarshalWith(SvipeIDCommonResponseSchema)
@require_user
def verify_identity(user: User, method: str, frontend_action: str, frontend_state: Optional[str] = None) -> FluxData:
    res = _authn(SvipeIDAction.verify_identity, method, frontend_action, frontend_state)
    if res.error:
        current_app.logger.error(f"Failed to start verify identity: {res.error}")
        return error_response(message=res.error)
    return success_response(payload={"location": res.url})


@dataclass
class AuthnResult:
    authn_req: Optional[RP_AuthnRequest] = None
    authn_id: Optional[OIDCState] = None
    error: Optional[TranslatableMsg] = None
    url: Optional[str] = None


def _authn(
    action: SvipeIDAction,
    method: str,
    frontend_action: str,
    frontend_state: Optional[str] = None,
) -> AuthnResult:
    current_app.logger.debug(f"Requested method: {method}, frontend action: {frontend_action}")

    try:
        auth_redirect = current_app.oidc_client.svipe.authorize_redirect(
            redirect_uri=url_for("svipe_id.authn_callback", _external=True)
        )
    except OAuthError:
        current_app.logger.exception("Failed to create authorization request")
        return AuthnResult(error=SvipeIDMsg.authn_request_failed)

    auth_url = auth_redirect.headers["Location"]
    auth_url_query = urlparse(auth_url).query
    try:
        # Ignore PyCharm warning "Expected type 'bytes' ..." for "state" lookup
        state = parse_qs(auth_url_query)["state"][0]
    except KeyError:
        current_app.logger.error(f'Failed to parse "state" from authn request: {auth_url_query}')
        return AuthnResult(error=SvipeIDMsg.authn_request_failed)

    proofing_method = get_proofing_method(method, frontend_action, current_app.conf)
    if not proofing_method:
        current_app.logger.error(f"Unknown method: {method}")
        return AuthnResult(error=SvipeIDMsg.method_not_available)

    session.svipe_id.rp.authns[OIDCState(state)] = RP_AuthnRequest(
        frontend_action=frontend_action,
        frontend_state=frontend_state,
        post_authn_action=action,
        method=proofing_method.method,
    )
    current_app.logger.debug(
        f"Stored RP_AuthnRequest[{OIDCState(state)}]: {session.svipe_id.rp.authns[OIDCState(state)]}"
    )
    current_app.logger.debug(f"returning url: {auth_url}")
    return AuthnResult(authn_id=OIDCState(state), url=auth_url, authn_req=session.svipe_id.rp.authns[OIDCState(state)])


@svipe_id_views.route("/authn-callback", methods=["GET"])
@require_user
def authn_callback(user) -> WerkzeugResponse:
    """
    This is the callback endpoint for the Svipe ID OIDC flow.
    """
    current_app.logger.debug("authn_callback called")
    current_app.logger.debug(f"request.args: {request.args}")
    authn_req = None
    oidc_state = None
    _oidc_state = request.args.get("state")
    if _oidc_state is not None:
        oidc_state = OIDCState(_oidc_state)
        authn_req = session.svipe_id.rp.authns.get(oidc_state)

    if not oidc_state or not authn_req:
        # Perhaps an authn response received out of order - abort without destroying state
        # (User makes two requests, A and B. Response B arrives, user is happy and proceeds with their work.
        #  Then response A arrives late. Just silently abort, no need to mess up the users' session.)
        current_app.logger.info(
            f"Response {oidc_state} does not match one in session, redirecting user to eduID Errors page"
        )
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn response", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.OIDC_RESPONSE_UNSOLICITED,
            rp=url_for("svipe_id.auth_callback", _external=True),
        )
    current_app.stats.count(name="authn_response")

    proofing_method = get_proofing_method(authn_req.method, authn_req.frontend_action, current_app.conf)
    if not proofing_method:
        # We _really_ shouldn't end up here because this same thing would have been done in the
        # starting views above.
        current_app.logger.warning(f"No proofing_method for method {authn_req.method}")
        if not current_app.conf.errors_url_template:
            return make_response("Unknown authn method", 400)
        return goto_errors_response(
            errors_url=current_app.conf.errors_url_template,
            ctx=EduidErrorsContext.OIDC_RESPONSE_FAIL,
            rp=url_for("svipe_id.auth_callback", _external=True),
        )

    formatted_finish_url = proofing_method.formatted_finish_url(app_name=current_app.conf.app_name, authn_id=oidc_state)
    assert formatted_finish_url  # please type checking

    try:
        token_response = current_app.oidc_client.svipe.authorize_access_token()
        current_app.logger.debug(f"Got token response: {token_response}")
        user_response = current_app.oidc_client.svipe.userinfo()
        current_app.logger.debug(f"Got user response: {user_response}")
        # TODO: look in to why we are not getting a full userinfo in token response anymore
        if not token_response.get("userinfo", dict).get("sub") == user_response.get("sub"):  # sub must match
            raise OAuthError("sub mismatch")
        user_response.update(token_response.get("userinfo", dict))
        current_app.logger.debug(f"merged user response and token respose userinfo: {user_response}")
    except (OAuthError, BadRequestKeyError):
        # catch any exception from the oidc client and also exceptions about missing request arguments
        current_app.logger.exception(f"Failed to get token response from Svipe ID")
        current_app.stats.count(name="token_response_failed")
        authn_req.error = True
        authn_req.status = SvipeIDMsg.authorization_error.value
        session.svipe_id.rp.authns[oidc_state] = authn_req
        return redirect(formatted_finish_url)

    # end session after successful token response
    try:
        metadata = current_app.oidc_client.svipe.load_server_metadata()
        current_app.oidc_client.svipe.get(
            metadata.get("end_session_endpoint"), params={"id_token_hint": token_response["id_token"]}
        )
    except OAuthError:
        # keep going even if we can't end the session
        current_app.logger.exception(f"Failed to end OIDC session")

    action = get_action(default_action=None, authndata=authn_req)
    backdoor = check_magic_cookie(config=current_app.conf)
    args = ACSArgs(
        session_info=user_response,
        authn_req=authn_req,
        proofing_method=proofing_method,
        backdoor=backdoor,
    )
    result = action(args=args)
    current_app.logger.debug(f"Callback action result: {result}")

    if not result.success:
        current_app.logger.info(f"OIDC callback action failed: {result.message}")
        current_app.stats.count(name="authn_action_failed")
        authn_req.error = True
        if result.message:
            authn_req.status = result.message.value
        session.svipe_id.rp.authns[oidc_state] = authn_req
        return redirect(formatted_finish_url)

    current_app.logger.debug(f"OIDC callback action successful (frontend_action {authn_req.frontend_action})")
    if result.message:
        authn_req.status = result.message.value
    session.svipe_id.rp.authns[oidc_state] = authn_req
    return redirect(formatted_finish_url)
