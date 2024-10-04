from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

from authlib.integrations.base_client import OAuthError
from flask import Blueprint, make_response, redirect, request, url_for
from werkzeug import Response as WerkzeugResponse

from eduid.common.config.base import FrontendAction
from eduid.userdb import User
from eduid.webapp.common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid.webapp.common.api.errors import EduidErrorsContext, goto_errors_response
from eduid.webapp.common.api.helpers import check_magic_cookie
from eduid.webapp.common.api.messages import AuthnStatusMsg, FluxData, TranslatableMsg, error_response, success_response
from eduid.webapp.common.api.schemas.authn_status import StatusRequestSchema, StatusResponseSchema
from eduid.webapp.common.api.schemas.csrf import EmptyResponse
from eduid.webapp.common.authn.acs_registry import ACSArgs, get_action
from eduid.webapp.common.proofing.methods import get_proofing_method
from eduid.webapp.common.session import session
from eduid.webapp.common.session.namespaces import OIDCState, RP_AuthnRequest
from eduid.webapp.freja_eid.app import current_freja_eid_app as current_app
from eduid.webapp.freja_eid.callback_enums import FrejaEIDAction
from eduid.webapp.freja_eid.helpers import FrejaEIDMsg
from eduid.webapp.freja_eid.schemas import FrejaEIDCommonRequestSchema, FrejaEIDCommonResponseSchema

__author__ = "lundberg"


freja_eid_views = Blueprint("freja_eid", __name__, url_prefix="")


@freja_eid_views.route("/", methods=["GET"])
@MarshalWith(EmptyResponse)
@require_user
def index(user: User) -> FluxData:
    return success_response(payload=None, message=None)


@freja_eid_views.route("/get-status", methods=["POST"])
@UnmarshalWith(StatusRequestSchema)
@MarshalWith(StatusResponseSchema)
def get_status(authn_id: OIDCState) -> FluxData:
    authn = session.freja_eid.rp.authns.get(authn_id)
    if not authn:
        return error_response(message=AuthnStatusMsg.not_found)

    payload = {
        "authn_id": str(authn_id),
        "frontend_action": authn.frontend_action.value,
        "frontend_state": authn.frontend_state,
        "method": authn.method,
        "error": bool(authn.error),
    }
    if authn.status is not None:
        payload["status"] = authn.status

    return success_response(payload=payload)


@freja_eid_views.route("/verify-identity", methods=["POST"])
@UnmarshalWith(FrejaEIDCommonRequestSchema)
@MarshalWith(FrejaEIDCommonResponseSchema)
@require_user
def verify_identity(user: User, method: str, frontend_action: str, frontend_state: str | None = None) -> FluxData:
    res = _authn(FrejaEIDAction.verify_identity, method, frontend_action, frontend_state)
    if res.error:
        current_app.logger.error(f"Failed to start verify identity: {res.error}")
        return error_response(message=res.error)
    return success_response(payload={"location": res.url})


@dataclass
class AuthnResult:
    authn_req: RP_AuthnRequest | None = None
    authn_id: OIDCState | None = None
    error: TranslatableMsg | None = None
    url: str | None = None


def _authn(
    action: FrejaEIDAction,
    method: str,
    frontend_action: str,
    frontend_state: str | None = None,
) -> AuthnResult:
    current_app.logger.debug(f"Requested method: {method}, frontend action: {frontend_action}")

    try:
        _frontend_action = FrontendAction(frontend_action)
        authn_params = current_app.conf.frontend_action_authn_parameters[_frontend_action]
    except (ValueError, KeyError):
        current_app.logger.exception(f"Frontend action {frontend_action} not supported")
        return AuthnResult(error=FrejaEIDMsg.frontend_action_not_supported)

    try:
        auth_redirect = current_app.oidc_client.freja_eid.authorize_redirect(
            redirect_uri=url_for("freja_eid.authn_callback", _external=True),
        )
    except OAuthError:
        current_app.logger.exception("Failed to create authorization request")
        return AuthnResult(error=FrejaEIDMsg.authn_request_failed)

    auth_url = auth_redirect.headers["Location"]
    auth_url_query = urlparse(auth_url).query
    try:
        # Ignore PyCharm warning "Expected type 'bytes' ..." for "state" lookup
        state = parse_qs(auth_url_query)["state"][0]
    except KeyError:
        current_app.logger.error(f'Failed to parse "state" from authn request: {auth_url_query}')
        return AuthnResult(error=FrejaEIDMsg.authn_request_failed)

    proofing_method = get_proofing_method(method, _frontend_action, current_app.conf)
    if not proofing_method:
        current_app.logger.error(f"Unknown method: {method}")
        return AuthnResult(error=FrejaEIDMsg.method_not_available)

    authn_req = RP_AuthnRequest(
        authn_id=OIDCState(state),
        frontend_action=_frontend_action,
        frontend_state=frontend_state,
        post_authn_action=action,
        method=proofing_method.method,
        finish_url=authn_params.finish_url,
    )
    session.freja_eid.rp.authns[authn_req.authn_id] = authn_req
    current_app.logger.debug(f"Stored RP_AuthnRequest[{authn_req.authn_id}]: {authn_req}")
    current_app.logger.debug(f"returning url: {auth_url}")
    return AuthnResult(authn_id=authn_req.authn_id, url=auth_url, authn_req=authn_req)


@freja_eid_views.route("/authn-callback", methods=["GET"])
@require_user
def authn_callback(user: User) -> WerkzeugResponse:
    """
    This is the callback endpoint for the Svipe ID OIDC flow.
    """
    current_app.logger.debug("authn_callback called")
    current_app.logger.debug(f"request.args: {request.args}")
    authn_req = None
    oidc_state: OIDCState | None = None
    if "state" in request.args:
        oidc_state = OIDCState(request.args["state"])
    if oidc_state is not None:
        authn_req = session.freja_eid.rp.authns.get(oidc_state)

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
            rp=url_for("freja_eid.authn_callback", _external=True),
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
            rp=url_for("freja_eid.authn_callback", _external=True),
        )

    formatted_finish_url = authn_req.formatted_finish_url(app_name=current_app.conf.app_name)
    assert formatted_finish_url  # please type checking

    try:
        token_response = current_app.oidc_client.freja_eid.authorize_access_token()
        current_app.logger.debug(f"Got token response: {token_response}")
    except (OAuthError, KeyError):
        # catch any exception from the oidc client and also exceptions about missing request arguments
        current_app.logger.exception("Failed to get token response from Freja")
        current_app.stats.count(name="token_response_failed")
        authn_req.error = True
        authn_req.status = FrejaEIDMsg.authorization_error.value
        return redirect(formatted_finish_url)

    action = get_action(default_action=None, authndata=authn_req)
    backdoor = check_magic_cookie(config=current_app.conf)
    args = ACSArgs(
        session_info=token_response.get("userinfo"),
        authn_req=authn_req,
        proofing_method=proofing_method,
        backdoor=backdoor,
    )
    result = action(args=args)
    current_app.logger.debug(f"Callback action result: {result}")

    if not result.success:
        current_app.logger.info(f"OIDC callback action failed: {result.message}")
        current_app.stats.count(name="authn_action_failed")
        args.authn_req.error = True
        if result.message:
            args.authn_req.status = result.message.value
        args.authn_req.consumed = True
        return redirect(formatted_finish_url)

    current_app.logger.debug(f"OIDC callback action successful (frontend_action {args.authn_req.frontend_action})")
    if result.message:
        args.authn_req.status = result.message.value
    args.authn_req.consumed = True
    return redirect(formatted_finish_url)
